import { useEffect, useState } from 'react';
import { BookOpen, CheckCircle2, Sparkles } from 'lucide-react';
import type { LearningProgressRecord, LearningTopic } from '../../shared/types';
import { apiRequest } from '../api/client';

export function LearningCenterPage({ initialTopicSlug }: { initialTopicSlug?: string }) {
  const [topics, setTopics] = useState<LearningTopic[]>([]);
  const [recommendedSlugs, setRecommendedSlugs] = useState<string[]>([]);
  const [progressMap, setProgressMap] = useState<Record<string, LearningProgressRecord>>({});
  const [selectedSlug, setSelectedSlug] = useState<string>(initialTopicSlug || 'sql-injection');
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [quizResult, setQuizResult] = useState<{ score: number; total: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const res = await apiRequest<{
          topics: LearningTopic[];
          recommendedSlugs: string[];
          progress: LearningProgressRecord[];
        }>('/api/learning/topics');
        if (!active) return;
        setTopics(res.topics);
        setRecommendedSlugs(res.recommendedSlugs);
        const map: Record<string, LearningProgressRecord> = {};
        for (const p of res.progress) map[p.topicSlug] = p;
        setProgressMap(map);
        if (initialTopicSlug && res.topics.some((t) => t.slug === initialTopicSlug)) {
          setSelectedSlug(initialTopicSlug);
        }
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load learning topics.');
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [initialTopicSlug]);

  const activeTopic = topics.find((t) => t.slug === selectedSlug) || topics[0];

  function selectTopic(slug: string) {
    setSelectedSlug(slug);
    setAnswers({});
    setQuizResult(null);
  }

  async function handleSubmitQuiz() {
    if (!activeTopic) return;
    let score = 0;
    for (const q of activeTopic.quiz) {
      if (answers[q.id] === q.correctIndex) score++;
    }
    const total = activeTopic.quiz.length;
    setQuizResult({ score, total });

    try {
      const res = await apiRequest<{ progress: LearningProgressRecord }>('/api/learning/progress', {
        method: 'POST',
        body: JSON.stringify({
          topicSlug: activeTopic.slug,
          quizScore: score,
          quizTotal: total,
        }),
      });
      setProgressMap((prev) => ({ ...prev, [activeTopic.slug]: res.progress }));
    } catch {
      // Non-blocking progress save
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
          Cybersecurity Learning Center
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Interactive secure coding guides, vulnerable vs. hardened examples, and knowledge checks tailored to your project findings.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="h-96 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Topic Curriculum List */}
          <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#0e1526] divide-y divide-slate-800/70 overflow-hidden">
            {topics.map((topic) => {
              const active = activeTopic?.slug === topic.slug;
              const recommended = recommendedSlugs.includes(topic.slug);
              const prog = progressMap[topic.slug];
              return (
                <button
                  key={topic.slug}
                  type="button"
                  onClick={() => selectTopic(topic.slug)}
                  className={`w-full text-left p-4 space-y-1 transition-colors ${
                    active ? 'bg-cyan-500/10' : 'hover:bg-slate-800/30'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-sm font-medium ${active ? 'text-cyan-300' : 'text-slate-100'}`}>
                      {topic.title}
                    </span>
                    {prog?.completed && (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono">{topic.cweId}</span>
                    {recommended && (
                      <>
                        <span>·</span>
                        <span className="inline-flex items-center gap-1 text-amber-300">
                          <Sparkles className="h-3 w-3" /> Recommended for your findings
                        </span>
                      </>
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Topic Content */}
          {activeTopic && (
            <div className="lg:col-span-8 space-y-6">
              <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono">
                    <BookOpen className="h-3.5 w-3.5" />
                    <span>{activeTopic.cweId}</span>
                    <span>·</span>
                    <span>{activeTopic.owaspCategory}</span>
                  </div>
                  <h2 className="font-display text-xl font-semibold text-slate-100">
                    {activeTopic.title}
                  </h2>
                  <p className="text-sm text-slate-300 leading-relaxed">{activeTopic.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-800 pt-4 text-sm">
                  <div className="space-y-1">
                    <p className="text-xs font-semibold text-slate-300">How It Happens</p>
                    <p className="text-slate-300 leading-relaxed">{activeTopic.explanation}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs font-semibold text-slate-300">Real-World Impact</p>
                    <p className="text-slate-300 leading-relaxed">{activeTopic.realWorldImpact}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-rose-300">
                      Vulnerable Example ({activeTopic.vulnerableLanguage})
                    </p>
                    <pre className="rounded-lg border border-rose-900/60 bg-[#060a14] p-3.5 font-mono text-xs text-rose-200 overflow-x-auto leading-5">
                      {activeTopic.vulnerableCode}
                    </pre>
                  </div>
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-emerald-300">
                      Secure Example ({activeTopic.vulnerableLanguage})
                    </p>
                    <pre className="rounded-lg border border-emerald-900/60 bg-[#060a14] p-3.5 font-mono text-xs text-emerald-200 overflow-x-auto leading-5">
                      {activeTopic.secureCode}
                    </pre>
                  </div>
                </div>

                <div className="space-y-2 border-t border-slate-800 pt-4">
                  <p className="text-xs font-semibold text-slate-300">Prevention Checklist</p>
                  <ul className="space-y-1.5 text-sm text-slate-300 list-disc pl-5">
                    {activeTopic.preventionMethods.map((m, idx) => (
                      <li key={idx}>{m}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Short Knowledge Quiz */}
              <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
                <div className="flex items-center justify-between">
                  <h3 className="font-display text-base font-semibold text-slate-100">
                    Knowledge Check
                  </h3>
                  {progressMap[activeTopic.slug] && (
                    <span className="font-mono text-xs text-emerald-400 tabular-nums">
                      Best Score: {progressMap[activeTopic.slug].quizScore}/
                      {progressMap[activeTopic.slug].quizTotal}
                    </span>
                  )}
                </div>

                <div className="space-y-5">
                  {activeTopic.quiz.map((q, qIdx) => (
                    <div key={q.id} className="space-y-2.5">
                      <p className="text-sm font-medium text-slate-200">
                        {qIdx + 1}. {q.question}
                      </p>
                      <div className="space-y-2">
                        {q.options.map((opt, optIdx) => {
                          const selected = answers[q.id] === optIdx;
                          return (
                            <label
                              key={optIdx}
                              className={`flex items-center gap-3 rounded-lg border px-3.5 py-2.5 text-xs cursor-pointer transition-colors ${
                                selected
                                  ? 'border-cyan-500/50 bg-cyan-500/10 text-slate-100'
                                  : 'border-slate-800 bg-[#080d1a] text-slate-300 hover:border-slate-700'
                              }`}
                            >
                              <input
                                type="radio"
                                name={q.id}
                                checked={selected}
                                onChange={() => setAnswers((prev) => ({ ...prev, [q.id]: optIdx }))}
                                className="accent-cyan-500"
                              />
                              <span>{opt}</span>
                            </label>
                          );
                        })}
                      </div>
                      {quizResult && (
                        <p
                          className={`text-xs ${
                            answers[q.id] === q.correctIndex ? 'text-emerald-400' : 'text-amber-300'
                          }`}
                        >
                          {answers[q.id] === q.correctIndex ? 'Correct: ' : 'Review: '}
                          {q.explanation}
                        </p>
                      )}
                    </div>
                  ))}
                </div>

                <div className="flex items-center justify-between gap-4 border-t border-slate-800 pt-4">
                  <button
                    type="button"
                    onClick={handleSubmitQuiz}
                    className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 whitespace-nowrap"
                  >
                    Submit Quiz Answers
                  </button>
                  {quizResult && (
                    <span className="font-mono text-sm text-slate-200 tabular-nums">
                      Score: {quizResult.score} / {quizResult.total}
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
