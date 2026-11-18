import React, { useEffect, useState } from 'react';
import { Bot, MessageSquarePlus, Send } from 'lucide-react';
import type { AIConversation, AIMessage, Project } from '../../shared/types';
import { apiRequest } from '../api/client';

const SUGGESTED_QUESTIONS = [
  'Which critical or high findings in this project should I fix first and why?',
  'Explain how SQL injection or command injection occurs in my project files.',
  'Are any of the pattern-based findings potential false positives?',
  'How should I safely manage API keys and environment variables in this codebase?',
];

export function AssistantPage({ initialProjectId }: { initialProjectId?: string }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [conversations, setConversations] = useState<AIConversation[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '');
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [projRes, convRes] = await Promise.all([
          apiRequest<{ projects: Project[] }>('/api/projects'),
          apiRequest<{ conversations: AIConversation[] }>('/api/ai/conversations'),
        ]);
        if (!active) return;
        setProjects(projRes.projects);
        setConversations(convRes.conversations);
        if (!selectedProjectId && projRes.projects.length > 0) {
          setSelectedProjectId(projRes.projects[0].id);
        }
        if (convRes.conversations.length > 0) {
          await selectConversation(convRes.conversations[0]);
        }
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load assistant workspace.');
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function selectConversation(conv: AIConversation) {
    setActiveConvId(conv.id);
    if (conv.projectId) setSelectedProjectId(conv.projectId);
    try {
      const res = await apiRequest<{ messages: AIMessage[] }>(
        `/api/ai/conversations/${conv.id}/messages`
      );
      setMessages(res.messages);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load messages.');
    }
  }

  function startNewConversation() {
    setActiveConvId(null);
    setMessages([]);
    setError(null);
  }

  async function handleSend(textToSend?: string) {
    const content = (textToSend ?? input).trim();
    if (!content || sending) return;
    setSending(true);
    setError(null);
    if (!textToSend) setInput('');

    try {
      const res = await apiRequest<{
        conversation: AIConversation;
        userMessage: AIMessage;
        assistantMessage: AIMessage;
      }>('/api/ai/chat', {
        method: 'POST',
        body: JSON.stringify({
          projectId: selectedProjectId || null,
          conversationId: activeConvId,
          message: content,
        }),
      });

      setActiveConvId(res.conversation.id);
      setMessages((prev) => [...prev, res.userMessage, res.assistantMessage]);
      setConversations((prev) => {
        const without = prev.filter((c) => c.id !== res.conversation.id);
        return [res.conversation, ...without];
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to contact AI Security Assistant.');
      if (!textToSend) setInput(content);
    } finally {
      setSending(false);
    }
  }

  function handleFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    handleSend();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
            AI Security Assistant
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Context-aware Gemini assistant grounded in your selected project, scanner findings, and remediation attempts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            aria-label="Project context"
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#0e1526] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="">General Security Context</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                Project: {p.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={startNewConversation}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0e1526] px-3 py-2 text-xs font-medium text-slate-200 hover:border-cyan-500/40 whitespace-nowrap"
          >
            <MessageSquarePlus className="h-3.5 w-3.5 text-cyan-400" />
            <span>New Chat</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="h-96 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Conversation History Sidebar */}
          <div className="lg:col-span-3 rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden flex flex-col max-h-[620px]">
            <div className="border-b border-slate-800 px-4 py-3 text-xs font-semibold text-slate-300">
              Saved Conversations
            </div>
            {conversations.length === 0 ? (
              <div className="p-4 text-xs text-slate-500">
                No previous conversations yet. Ask a question to begin.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/70 overflow-y-auto">
                {conversations.map((c) => {
                  const active = c.id === activeConvId;
                  return (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => selectConversation(c)}
                      className={`w-full text-left px-4 py-3 space-y-1 transition-colors ${
                        active ? 'bg-cyan-500/10' : 'hover:bg-slate-800/30'
                      }`}
                    >
                      <p className={`text-xs font-medium truncate ${active ? 'text-cyan-300' : 'text-slate-200'}`}>
                        {c.title}
                      </p>
                      <p className="text-[11px] text-slate-500 truncate">
                        {c.projectName || 'General'} · {new Date(c.updatedAt).toLocaleDateString()}
                      </p>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Chat Area */}
          <div className="lg:col-span-9 rounded-xl border border-slate-800 bg-[#0e1526] flex flex-col h-[620px] overflow-hidden">
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center max-w-lg mx-auto space-y-5">
                  <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
                    <Bot className="h-5 w-5" />
                  </div>
                  <div className="space-y-1.5">
                    <h2 className="font-display text-base font-semibold text-slate-100">
                      Ask About Your Project Security
                    </h2>
                    <p className="text-xs text-slate-400">
                      Responses reference your real uploaded project findings, scanner outputs, and secure coding standards.
                    </p>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full text-left">
                    {SUGGESTED_QUESTIONS.map((q) => (
                      <button
                        key={q}
                        type="button"
                        onClick={() => handleSend(q)}
                        className="rounded-lg border border-slate-800 bg-[#080d1a] p-3 text-xs text-slate-300 hover:border-cyan-500/40 hover:text-slate-100 transition-colors"
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                messages.map((m) => (
                  <div
                    key={m.id}
                    className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[85%] rounded-xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                        m.role === 'user'
                          ? 'bg-cyan-500/15 border border-cyan-500/30 text-slate-100'
                          : 'bg-[#080d1a] border border-slate-800 text-slate-200'
                      }`}
                    >
                      {m.content}
                      {m.modelName && (
                        <p className="mt-2 font-mono text-[10px] text-slate-500">
                          {m.modelName} · Advisory output
                        </p>
                      )}
                    </div>
                  </div>
                ))
              )}

              {sending && (
                <div className="flex justify-start">
                  <div className="rounded-xl border border-slate-800 bg-[#080d1a] px-4 py-3 text-xs text-slate-400">
                    Analyzing project findings and drafting response...
                  </div>
                </div>
              )}
            </div>

            <form onSubmit={handleFormSubmit} className="border-t border-slate-800 p-4 flex items-center gap-3 bg-[#0b1120]">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={sending}
                placeholder="Ask about a finding, remediation step, or secure coding pattern..."
                className="flex-1 rounded-lg border border-slate-800 bg-[#080d1a] px-4 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={sending || !input.trim()}
                className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                <Send className="h-3.5 w-3.5" />
                <span>Send</span>
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
