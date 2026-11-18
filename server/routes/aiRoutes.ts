import { Router } from 'express';
import { analyzeFindingWithGemini, chatWithSecurityAssistant } from '../ai/aiService.ts';
import { GeminiServiceError, getGeminiStatus } from '../ai/geminiClient.ts';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';

export const aiRoutes = Router();
aiRoutes.use(requireAuth, requireCsrf);

aiRoutes.get('/status', (_req, res) => {
  res.json(getGeminiStatus());
});

aiRoutes.post('/analyze', async (req: AuthenticatedRequest, res) => {
  const { findingId } = req.body || {};
  if (!findingId || typeof findingId !== 'string') {
    res.status(400).json({ error: 'findingId is required.' });
    return;
  }

  try {
    const analysis = await analyzeFindingWithGemini({
      findingId,
      userId: req.auth!.userId,
      modelOverride: req.auth!.user.preferredModel,
    });
    res.status(201).json({ analysis });
  } catch (err) {
    if (err instanceof GeminiServiceError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to analyze finding with Gemini AI.' });
  }
});

aiRoutes.post('/chat', async (req: AuthenticatedRequest, res) => {
  const { projectId, conversationId, message } = req.body || {};
  if (!message || typeof message !== 'string') {
    res.status(400).json({ error: 'message is required.' });
    return;
  }

  try {
    const result = await chatWithSecurityAssistant({
      userId: req.auth!.userId,
      projectId: projectId ? String(projectId) : null,
      conversationId: conversationId ? String(conversationId) : null,
      message,
      modelOverride: req.auth!.user.preferredModel,
    });
    res.json(result);
  } catch (err) {
    if (err instanceof GeminiServiceError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to communicate with AI Security Assistant.' });
  }
});

aiRoutes.get('/conversations', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT c.*, p.name AS project_name
       FROM ai_conversations c
       LEFT JOIN projects p ON p.id = c.project_id
       WHERE c.user_id = ?
       ORDER BY c.updated_at DESC
       LIMIT 30`
    )
    .all(req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    conversations: rows.map((c) => ({
      id: String(c.id),
      userId: String(c.user_id),
      projectId: c.project_id ? String(c.project_id) : null,
      projectName: c.project_name ? String(c.project_name) : null,
      title: String(c.title),
      createdAt: String(c.created_at),
      updatedAt: String(c.updated_at),
    })),
  });
});

aiRoutes.get('/conversations/:id/messages', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const conv = db
    .prepare('SELECT id FROM ai_conversations WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!conv) {
    res.status(404).json({ error: 'Conversation not found.' });
    return;
  }

  const rows = db
    .prepare('SELECT * FROM ai_messages WHERE conversation_id = ? ORDER BY created_at ASC')
    .all(req.params.id) as Array<Record<string, unknown>>;

  res.json({
    messages: rows.map((m) => ({
      id: String(m.id),
      conversationId: String(m.conversation_id),
      role: m.role,
      content: String(m.content),
      modelName: m.model_name ? String(m.model_name) : null,
      createdAt: String(m.created_at),
    })),
  });
});
