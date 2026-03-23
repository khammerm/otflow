// api/generate.js — OTFlow, hardened & secure

import crypto from 'crypto';

const rateMap = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60_000;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) { rateMap.set(ip, { count: 1, start: now }); return false; }
  if (entry.count >= RATE_LIMIT) return true;
  entry.count++;
  rateMap.set(ip, entry);
  return false;
}

function verifyToken(token) {
  const secret = process.env.TOKEN_SECRET;
  if (!secret || !token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [b64payload, sig] = parts;
  const payload = Buffer.from(b64payload, 'base64url').toString();
  const [, expiry] = payload.split(':');
  if (!expiry || Date.now() > parseInt(expiry)) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

const ALLOWED_TYPES = ['Individual OT session','Group OT session','Initial evaluation','Re-evaluation','Home visit','Telehealth session'];
const ALLOWED_FORMATS = ['DAP', 'SOAP', 'SIRP'];

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const allowedOrigins = [process.env.ALLOWED_ORIGIN, 'http://localhost:3000'].filter(Boolean);
  const origin = req.headers['origin'] || '';
  if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  if (isRateLimited(ip)) return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const isPro = token ? verifyToken(token) : false;

  const { notes, clientId, sessionDate, sessionType, noteFormat } = req.body || {};
  if (!notes || typeof notes !== 'string') return res.status(400).json({ error: 'Missing session notes.' });
  const trimmed = notes.trim();
  if (trimmed.length < 20)   return res.status(400).json({ error: 'Session summary is too short.' });
  if (trimmed.length > 4000) return res.status(400).json({ error: 'Session summary is too long (max 4000 chars).' });

  const safeClient = (clientId || '').replace(/[^a-zA-Z0-9 .\-]/g, '').slice(0, 20);
  const safeDate   = (sessionDate || '').replace(/[^0-9\-]/g, '').slice(0, 10);
  const safeType   = ALLOWED_TYPES.includes(sessionType) ? sessionType : 'Individual OT session';
  const safeFormat = ALLOWED_FORMATS.includes(noteFormat) ? noteFormat : 'DAP';

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) { console.error('GEMINI_API_KEY not set'); return res.status(500).json({ error: 'Server configuration error.' }); }

  const formatGuides = {
    DAP: `Respond ONLY with a valid JSON object with exactly three keys: "D", "A", "P"
- D (Data): Objective and subjective data observed during the session. Client's presentation, performance on tasks, measurable outcomes, functional observations. Use "Client demonstrated..." or "Client reported..."
- A (Assessment): Therapist's clinical interpretation of the data. Progress toward goals, functional implications, clinical reasoning, barriers to progress.
- P (Plan): Next steps — upcoming interventions, goal modifications, home program updates, frequency of treatment, referrals if needed.`,

    SOAP: `Respond ONLY with a valid JSON object with exactly four keys: "S", "O", "A", "P"
- S (Subjective): Client's self-reported experience, complaints, goals, and concerns.
- O (Objective): Measurable, observable data — range of motion, strength, standardized test scores, task performance.
- A (Assessment): Clinical interpretation, progress toward OT goals, functional implications.
- P (Plan): Treatment plan, home program, next session focus, referrals.`,

    SIRP: `Respond ONLY with a valid JSON object with exactly four keys: "S", "I", "R", "P"
- S (Situation): Client's current status, reason for session, presenting issues.
- I (Intervention): What the OT did — specific techniques, activities, education, modifications used.
- R (Response): How the client responded to interventions — engagement, performance, affect, functional outcomes.
- P (Plan): Next session plan, home program, goal updates, follow-up needed.`
  };

  const systemPrompt = `You are an expert occupational therapy documentation specialist helping licensed OTs write professional clinical notes.
${formatGuides[safeFormat]}
No markdown, no backticks, no explanation — just the raw JSON object.
Each section: 2–5 sentences. Professional, specific, functionally focused, clinically accurate.
Use OT-specific language: functional independence, ADLs, IADLs, fine motor, gross motor, sensory processing, therapeutic use of occupation, compensatory strategies, adaptive equipment.`;

  const userPrompt = `Note Format: ${safeFormat}
Session Type: ${safeType}
Client: ${safeClient || 'Client'}
Date: ${safeDate || 'Not specified'}

Therapist summary:
${trimmed}

Generate the ${safeFormat} note JSON now.`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          generationConfig: { temperature: 0.3, maxOutputTokens: 1024 }
        })
      }
    );

    if (!response.ok) {
      const err = await response.json();
      console.error('Gemini error:', err);
      throw new Error('AI service error. Please try again.');
    }

    const data = await response.json();
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const clean = raw.replace(/```json|```/g, '').trim();

    let note;
    try { note = JSON.parse(clean); }
    catch { throw new Error('Could not parse generated note. Please try again.'); }

    const requiredKeys = safeFormat === 'DAP' ? ['D','A','P'] : safeFormat === 'SOAP' ? ['S','O','A','P'] : ['S','I','R','P'];
    if (!requiredKeys.every(k => note[k])) throw new Error('Incomplete note generated. Please try again.');

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    return res.status(200).json({ note, format: safeFormat, isPro });

  } catch (err) {
    console.error('Handler error:', err.message);
    return res.status(500).json({ error: err.message || 'Failed to generate note.' });
  }
}
