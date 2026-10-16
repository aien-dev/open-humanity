//! Teaching steps scaled to passage length (follow-up F1).
//!
//! Setup copies `scripts/demo-teach.sh`: corpus = repository LICENSE, held-out
//! fraction 0.1, one volunteer slot, dim 32, seed 1, run steps 500. Three
//! fixed passages written in the style of the Qwen replies from the first
//! runs stand in for teaching batches, so the numbers repeat without a
//! network. Print the numbers with
//! `cargo test --release -p oh-coordinator --test teaching_steps -- --ignored --nocapture`.

use beacon_core::Keypair;
use oh_coordinator::{split_corpus, teaching_seed, Coordinator, Settings, TeachingVerdict};
use oh_core::{text_digest, Learner, Ledger, Scorer, TeachingBatch, TinyByteModel};

const LICENSE: &[u8] = include_bytes!("../../../LICENSE");

const PASSAGE_1: &[u8] =
    b"A free software license gives every person who receives a program the same \
freedoms as the person who wrote it. You may run the program for any purpose, study how it works, \
change it so it does what you need, and share copies with your neighbours. When you pass the \
program on, you must pass these freedoms on as well, so that nobody further down the line can \
take them away. The license asks that you keep the copyright notices intact and that you make \
the source code available to anyone who receives the program from you. These conditions protect \
the community that builds the software and make sure the work stays open for everyone.";

const PASSAGE_2: &[u8] =
    b"Volunteers who share their work under a public license help everyone who \
comes after them. Each person can read the source, learn from it, fix what is broken, and add \
something new. If you modify the program and give it to others, you must tell them what you \
changed and share your changes under the same terms. This keeps the program free as it grows. \
No one may add extra restrictions that would stop others from using the rights the license \
grants to every person who receives a copy of the work.";

const PASSAGE_3: &[u8] =
    b"Software that anyone may copy and improve grows through many small gifts of \
time. A person finds a problem, writes a fix, and sends it back so that every other user gets the \
same benefit. The license is the agreement that makes this safe: it says what each person may do \
with the code and what they must give in return. Because the terms are the same for everyone, a \
student, a company and a volunteer can all build on the same work and trust that it will stay \
open for the people who come after them.";

const ORDERS: [[&[u8]; 3]; 3] = [
    [PASSAGE_1, PASSAGE_2, PASSAGE_3],
    [PASSAGE_3, PASSAGE_1, PASSAGE_2],
    [PASSAGE_2, PASSAGE_3, PASSAGE_1],
];

const RUN_STEPS: u32 = 500;

fn settings() -> Settings {
    Settings {
        volunteers_per_round: 1,
        steps: RUN_STEPS,
        heldout_fraction: 0.1,
        seed: 1,
        dim: 32,
    }
}

fn fresh_ledger(name: &str) -> Ledger {
    let dir = std::env::temp_dir().join(format!("oh-steps-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Ledger::open(&dir.join("ledger.jsonl")).unwrap()
}

/// One teaching batch per round through the real coordinator, as in
/// demo-teach.sh. Returns each batch's Turings.
fn coordinator_chain(order: [&[u8]; 3], name: &str) -> Vec<f64> {
    let mut coordinator = Coordinator::new(LICENSE, &settings(), fresh_ledger(name)).unwrap();
    let node = Keypair::generate();
    let mut out = Vec::new();
    for text in order {
        coordinator.begin_round();
        let unit = coordinator.work_unit(0);
        let batch = TeachingBatch::new_signed(&node, &unit, text.to_vec());
        let accepted = match coordinator.judge_teaching(&unit, &batch).unwrap() {
            TeachingVerdict::Accepted { receipt, text } => {
                out.push(receipt.turings);
                vec![text]
            }
            TeachingVerdict::Rejected { receipt, .. } => {
                out.push(receipt.turings);
                Vec::new()
            }
            TeachingVerdict::Dropped(reason) => panic!("dropped: {reason}"),
        };
        coordinator.finish_round_with_teaching(&[], &accepted);
    }
    out
}

/// The version 0 rule (every batch trains for the run's 500 steps), run
/// outside the coordinator for comparison.
fn fixed_steps_chain(order: [&[u8]; 3]) -> Vec<f64> {
    let (_, heldout) = split_corpus(LICENSE, 0.1).unwrap();
    let mut model = TinyByteModel::new(32, 1);
    let mut out = Vec::new();
    for text in order {
        let scorer = Scorer {
            base: model.params(),
            heldout: heldout.to_vec(),
            epsilon: oh_coordinator::EPSILON,
        };
        let seed = teaching_seed(&text_digest(text));
        let t = scorer.score_text(&mut model, text, RUN_STEPS as usize, seed);
        if scorer.accept(t) {
            model.train_steps(text, RUN_STEPS as usize, seed);
        }
        out.push(t);
    }
    out
}

#[test]
fn test_fixed_steps_overfit_short_passages() {
    // The version 0 failure, reproduced: after one passage is trained on,
    // 500 steps on the next ~500 byte passage raise held-out bits.
    for order in ORDERS {
        let t = fixed_steps_chain(order);
        assert!(t[0] > 0.0, "{t:?}");
        assert!(t[1] < 0.0, "expected the second batch to overfit: {t:?}");
    }
}

#[test]
fn test_every_batch_of_similar_english_scores_positive_with_scaled_steps() {
    for (i, order) in ORDERS.into_iter().enumerate() {
        let t = coordinator_chain(order, &format!("order{i}"));
        assert!(t.iter().all(|&v| v > 0.0), "order {i}: {t:?}");
    }
}

#[test]
#[ignore]
fn print_teaching_steps_measurement() {
    for (i, order) in ORDERS.into_iter().enumerate() {
        let lens: Vec<usize> = order.iter().map(|p| p.len()).collect();
        let fmt = |t: &[f64]| {
            t.iter()
                .map(|v| format!("{v:+.3}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        eprintln!("order {i} lengths {lens:?}");
        eprintln!("  fixed 500 steps: {}", fmt(&fixed_steps_chain(order)));
        eprintln!(
            "  scaled steps:    {}",
            fmt(&coordinator_chain(order, &format!("print{i}")))
        );
    }
}
