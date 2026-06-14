//! Stateful streaming scanner.
//!
//! Output arrives chunk-by-chunk. We keep an overlap window so patterns that
//! straddle two chunks (a secret, a PII value, a placeholder, a URL) are still
//! detected and not emitted half-way. Trade-off: a larger window catches longer
//! cross-chunk patterns but holds back more text (higher latency); a smaller one
//! streams sooner but can miss long patterns. Default overlap: 1 KiB.

use crate::pii::{self, Entity};
use crate::types::{Finding, Risk, Vault};
use crate::{secrets, urls};

pub const DEFAULT_OVERLAP: usize = 1024;

/// Streaming configuration.
pub struct StreamConfig {
    /// Bytes of overlap held back between chunks.
    pub overlap: usize,
    /// Cut the stream when a finding at or above this risk is emitted.
    pub cut_at: Risk,
    pub secret_leak: bool,
    pub malicious_urls: bool,
    /// PII entities to detect in the output (empty = none).
    pub pii_entities: Vec<Entity>,
    /// Vault used to restore PII placeholders on the fly.
    pub vault: Vault,
}

impl Default for StreamConfig {
    fn default() -> Self {
        StreamConfig {
            overlap: DEFAULT_OVERLAP,
            cut_at: Risk::Critical,
            secret_leak: true,
            malicious_urls: true,
            pii_entities: Vec::new(),
            vault: Vault::new(),
        }
    }
}

/// The result of feeding one chunk (or finishing).
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamStep {
    /// Text safe to emit now (PII restored from the vault).
    pub output: String,
    /// Findings finalized in this step (absolute spans into the full stream).
    pub findings: Vec<Finding>,
    /// True once a cut-level finding was seen; the stream should stop.
    pub cut: bool,
}

pub struct StreamScanner {
    cfg: StreamConfig,
    buf: String,
    base: usize,
    done: bool,
}

impl StreamScanner {
    pub fn new(cfg: StreamConfig) -> Self {
        StreamScanner {
            cfg,
            buf: String::new(),
            base: 0,
            done: false,
        }
    }

    fn scan_window(&self, text: &str) -> Vec<Finding> {
        let mut f = Vec::new();
        if self.cfg.secret_leak {
            f.extend(secrets::scan_leak(text));
        }
        if self.cfg.malicious_urls {
            f.extend(urls::scan(text));
        }
        if !self.cfg.pii_entities.is_empty() {
            f.extend(pii::scan(text, &self.cfg.pii_entities));
        }
        f
    }

    fn step(&mut self, flush_all: bool) -> StreamStep {
        if self.done {
            return StreamStep {
                output: String::new(),
                findings: Vec::new(),
                cut: false,
            };
        }
        let n = self.buf.len();
        let mut flush_point = if flush_all {
            n
        } else {
            n.saturating_sub(self.cfg.overlap)
        };

        let local = self.scan_window(&self.buf);

        // Don't flush across a finding or a vault placeholder that straddles the
        // boundary — keep it in the carry until it is complete.
        if !flush_all {
            let protect = |start: usize, end: usize, fp: &mut usize| {
                if start < *fp && end > *fp {
                    *fp = start;
                }
            };
            for f in &local {
                if let Some([s, e]) = f.span {
                    protect(s, e, &mut flush_point);
                }
            }
            for key in self.cfg.vault.keys() {
                for (s, _) in self.buf.match_indices(key.as_str()) {
                    protect(s, s + key.len(), &mut flush_point);
                }
            }
            while flush_point > 0 && !self.buf.is_char_boundary(flush_point) {
                flush_point -= 1;
            }
        }

        // Findings fully inside the flushed region are final.
        let mut emitted: Vec<Finding> = local
            .into_iter()
            .filter(|f| f.span.map(|[_, e]| e <= flush_point).unwrap_or(false))
            .collect();

        // Cut handling: never stream out content at/after the first cut-level hit.
        let mut cut = false;
        let mut out_end = flush_point;
        if let Some(min_start) = emitted
            .iter()
            .filter(|f| f.risk >= self.cfg.cut_at)
            .filter_map(|f| f.span.map(|[s, _]| s))
            .min()
        {
            cut = true;
            out_end = min_start;
        }

        let output = pii::restore(&self.buf[..out_end], &self.cfg.vault);

        // Shift emitted spans to absolute offsets.
        for f in &mut emitted {
            if let Some([s, e]) = f.span {
                f.span = Some([self.base + s, self.base + e]);
            }
        }

        if cut || flush_all {
            self.done = true;
            self.buf.clear();
        } else {
            self.buf = self.buf[flush_point..].to_string();
            self.base += flush_point;
        }

        StreamStep {
            output,
            findings: emitted,
            cut,
        }
    }

    /// Feed the next chunk.
    pub fn push(&mut self, chunk: &str) -> StreamStep {
        self.buf.push_str(chunk);
        self.step(false)
    }

    /// Flush all remaining buffered text (end of stream).
    pub fn finish(&mut self) -> StreamStep {
        self.step(true)
    }
}
