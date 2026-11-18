import { Router } from 'express';
import crypto from 'node:crypto';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';
import { LEARNING_TOPICS, recommendTopicsForCategories } from '../learning/learningTopics.ts';

export const learningRoutes = Router();
learningRoutes.use(requireAuth, requireCsrf);

learningRoutes.get('/topics', (req: AuthenticatedRequest, res) => {
  const db = getDb();

  const progressRows = db
    .prepare('SELECT topic_slug, quiz_score, quiz_total, completed, updated_at FROM learning_progress WHERE user_id = ?')
    .all(req.auth!.userId) as Array<{
    topic_slug: string;
    quiz_score: number;
    quiz_total: number;
    completed: number;
    updated_at: string;
  }>;

  const openCategoryRows = db
    .prepare(
      `SELECT DISTINCT category FROM findings
       WHERE user_id = ? AND remediation_status IN ('open', 'in_review')`
    )
    .all(req.auth!.userId) as Array<{ category: string }>;

  const recommended = recommendTopicsForCategories(openCategoryRows.map((r) => r.category));

  res.json({
    topics: LEARNING_TOPICS,
    recommendedSlugs: recommended.map((t) => t.slug),
    progress: progressRows.map((p) => ({
      topicSlug: p.topic_slug,
      quizScore: p.quiz_score,
      quizTotal: p.quiz_total,
      completed: Boolean(p.completed),
      updatedAt: p.updated_at,
    })),
  });
});

learningRoutes.post('/progress', (req: AuthenticatedRequest, res) => {
  const { topicSlug, quizScore, quizTotal } = req.body || {};
  const topic = LEARNING_TOPICS.find((t) => t.slug === topicSlug);
  if (!topic) {
    res.status(404).json({ error: 'Learning topic not found.' });
    return;
  }

  const score = Math.max(0, Math.min(topic.quiz.length, Number(quizScore || 0)));
  const total = Math.max(1, Number(quizTotal || topic.quiz.length));
  const completed = score === total ? 1 : 0;
  const now = new Date().toISOString();

  const db = getDb();
  db.prepare(
    `INSERT INTO learning_progress (id, user_id, topic_slug, quiz_score, quiz_total, completed, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, topic_slug) DO UPDATE SET
       quiz_score = excluded.quiz_score,
       quiz_total = excluded.quiz_total,
       completed = excluded.completed,
       updated_at = excluded.updated_at`
  ).run(crypto.randomUUID(), req.auth!.userId, topic.slug, score, total, completed, now);

  res.json({
    progress: {
      topicSlug: topic.slug,
      quizScore: score,
      quizTotal: total,
      completed: Boolean(completed),
      updatedAt: now,
    },
  });
});
