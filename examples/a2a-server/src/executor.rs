//! The demo skill: a deterministic summarizer. The interesting part of this
//! example is the gate around it, not the model behind it — so there is no
//! model: the "summary" is the first sentence plus a word count, and the
//! task lifecycle (working → completed / canceled) is real SDK machinery.

use a2a::event::StreamResponse;
use a2a::*;
use a2a_server::{AgentExecutor, ExecutorContext};
use futures::stream::{self, BoxStream};

pub struct SummarizeExecutor;

fn summarize(text: &str) -> String {
    let first = text.split(['.', '!', '?']).next().unwrap_or("").trim();
    let words = text.split_whitespace().count();
    format!("{first} ({words} words)")
}

impl AgentExecutor for SummarizeExecutor {
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();

        let input: String = ctx
            .message
            .as_ref()
            .map(|m| {
                m.parts
                    .iter()
                    .filter_map(|p| match &p.content {
                        PartContent::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        let working = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: task_id.clone(),
            context_id: context_id.clone(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            metadata: None,
        });

        let completed = StreamResponse::Task(Task {
            id: task_id.clone(),
            context_id: context_id.clone(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(Message {
                    role: Role::Agent,
                    message_id: new_message_id(),
                    task_id: Some(task_id),
                    context_id: Some(context_id),
                    parts: vec![Part::text(summarize(&input))],
                    metadata: None,
                    extensions: None,
                    reference_task_ids: None,
                }),
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        });

        Box::pin(stream::iter([Ok(working), Ok(completed)]))
    }

    fn cancel(&self, ctx: ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        Box::pin(stream::once(async {
            Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id,
                context_id,
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: Some(chrono::Utc::now()),
                },
                metadata: None,
            }))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::summarize;

    #[test]
    fn summary_is_deterministic() {
        assert_eq!(
            summarize("Agents need receipts. Trust needs proofs."),
            "Agents need receipts (6 words)"
        );
    }
}
