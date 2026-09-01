//! One worker-wide clock for transport keepalive scheduling.
//!
//! The clock sends ticks, never USB frames. Each transport thread remains the
//! sole writer of its endpoint and translates ticks into its own wire format.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

enum Command {
    Subscribe {
        id: u64,
        initial_delay: Duration,
        interval: Duration,
        ticks: SyncSender<()>,
        ready: SyncSender<()>,
    },
    Unsubscribe(u64),
    Shutdown,
}

struct Entry {
    next: Instant,
    interval: Duration,
    ticks: SyncSender<()>,
}

pub(crate) struct Scheduler {
    commands: mpsc::Sender<Command>,
    thread: Option<JoinHandle<()>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone)]
pub(crate) struct Handle {
    commands: mpsc::Sender<Command>,
    next_id: Arc<AtomicU64>,
}

pub(crate) struct Subscription {
    id: u64,
    commands: mpsc::Sender<Command>,
    ticks: Receiver<()>,
}

impl Scheduler {
    pub(crate) fn start() -> io::Result<Self> {
        let (commands, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("keepalive-clock".to_owned())
            .spawn(move || run(receiver))?;
        Ok(Self {
            commands,
            thread: Some(thread),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub(crate) fn handle(&self) -> Handle {
        Handle {
            commands: self.commands.clone(),
            next_id: Arc::clone(&self.next_id),
        }
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Handle {
    pub(crate) fn subscribe(
        &self,
        initial_delay: Duration,
        interval: Duration,
    ) -> io::Result<Subscription> {
        if interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "keepalive interval must be nonzero",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (ticks, receiver) = mpsc::sync_channel(1);
        let (ready, subscribed) = mpsc::sync_channel(0);
        self.commands
            .send(Command::Subscribe {
                id,
                initial_delay,
                interval,
                ticks,
                ready,
            })
            .map_err(|_| io::Error::other("keepalive clock stopped"))?;
        subscribed
            .recv()
            .map_err(|_| io::Error::other("keepalive clock stopped during subscription"))?;
        Ok(Subscription {
            id,
            commands: self.commands.clone(),
            ticks: receiver,
        })
    }
}

impl Subscription {
    pub(crate) fn tick_due(&self) -> bool {
        let due = self.ticks.try_recv().is_ok();
        while self.ticks.try_recv().is_ok() {}
        due
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Unsubscribe(self.id));
    }
}

fn run(commands: Receiver<Command>) {
    let mut entries = BTreeMap::<u64, Entry>::new();
    loop {
        let received = match entries.values().map(|entry| entry.next).min() {
            Some(next) => commands.recv_timeout(next.saturating_duration_since(Instant::now())),
            None => commands.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(Command::Subscribe {
                id,
                initial_delay,
                interval,
                ticks,
                ready,
            }) => {
                entries.insert(
                    id,
                    Entry {
                        next: Instant::now() + initial_delay,
                        interval,
                        ticks,
                    },
                );
                let _ = ready.send(());
            }
            Ok(Command::Unsubscribe(id)) => {
                entries.remove(&id);
            }
            Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        emit_due(&mut entries);
    }
}

fn emit_due(entries: &mut BTreeMap<u64, Entry>) {
    let now = Instant::now();
    entries.retain(|_, entry| {
        if entry.next > now {
            return true;
        }
        let connected = match entry.ticks.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) => true,
            Err(TrySendError::Disconnected(())) => false,
        };
        while entry.next <= now {
            entry.next += entry.interval;
        }
        connected
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn await_tick(subscription: &Subscription, deadline: Instant) -> bool {
        while Instant::now() < deadline {
            if subscription.tick_due() {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    fn one_clock_ticks_independent_subscriptions_without_backlog() {
        let scheduler = Scheduler::start().unwrap();
        let handle = scheduler.handle();
        let fast = handle
            .subscribe(Duration::ZERO, Duration::from_millis(5))
            .unwrap();
        let slow = handle
            .subscribe(Duration::from_millis(15), Duration::from_millis(10))
            .unwrap();

        let deadline = Instant::now() + Duration::from_millis(250);
        assert!(await_tick(&fast, deadline));
        assert!(!slow.tick_due());
        assert!(await_tick(&slow, deadline));

        thread::sleep(Duration::from_millis(30));
        assert!(fast.tick_due());
        assert!(!fast.tick_due(), "ticks are coalesced instead of queued");
    }

    #[test]
    fn zero_interval_is_rejected() {
        let scheduler = Scheduler::start().unwrap();
        assert!(
            scheduler
                .handle()
                .subscribe(Duration::ZERO, Duration::ZERO)
                .is_err()
        );
    }
}
