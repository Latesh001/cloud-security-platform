import { useEffect, useRef, useState } from 'react';
import api from '../../services/api';
import Markdown from '../../components/Markdown';
import { Notice } from './shared';

const STARTERS = [
  'Explain the top vulnerability in my latest scan',
  'What is CVE-2021-44228 and how do I fix it?',
  'How does Phase 1 scoring work in this platform?',
  'Write a Python function that hashes a file with SHA-256',
  'How does Phase 3 incident response work in this platform?',
];

const SOURCE_LABELS = {
  gemini: 'Google Gemini',
  openai: 'OpenAI',
  knowledge_base: 'Knowledge base',
  error: 'Unavailable',
};

export default function Assistant() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [projectId, setProjectId] = useState('');
  const [projects, setProjects] = useState([]);
  const endRef = useRef(null);

  const load = () => {
    api.get('/advanced/chat/history')
      .then((r) => setMessages(r.data.messages || []))
      .catch(() => setMessages([]));
  };

  useEffect(() => { load(); }, []);
  useEffect(() => {
    api.get('/projects')
      .then((r) => {
        const list = r.data.projects || [];
        setProjects(list);
        if (!projectId && list[0]) setProjectId(list[0].project_id);
      })
      .catch(() => setProjects([]));
  }, []);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = async (text) => {
    const content = (text || input).trim();
    if (!content || sending) return;
    setInput('');
    setSending(true);
    setError('');
    setMessages((prev) => [...prev, { role: 'user', content, created_at: new Date().toISOString() }]);
    try {
      const { data } = await api.post('/advanced/chat', {
        message: content,
        question: content,
        project_id: projectId || undefined,
      }, { timeout: 25000 });
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: data.reply || data.answer,
        source: data.source,
        created_at: new Date().toISOString(),
      }]);
    } catch (err) {
      const timedOut = err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '');
      setError(timedOut
        ? 'The assistant took too long. Try a shorter question.'
        : (err.response?.data?.error || 'The assistant could not reply.'));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">AI Security Assistant</h1>
        <p className="text-gray-500">
          Powered by Google Gemini. Ask anything — this product, your scans, CVEs, code, or general questions.
        </p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      <div className="flex flex-wrap gap-2">
        {STARTERS.map((s) => (
          <button key={s} type="button" className="btn-secondary text-xs" onClick={() => send(s)}>{s}</button>
        ))}
      </div>
      <select
        className="input-field max-w-md"
        value={projectId}
        onChange={(e) => setProjectId(e.target.value)}
      >
        <option value="">No project context</option>
        {projects.map((p) => (
          <option key={p.project_id} value={p.project_id}>
            {p.project_id} · {p.project_name}
          </option>
        ))}
      </select>
      <div className="card h-[28rem] overflow-y-auto space-y-3">
        {messages.length === 0 && (
          <p className="text-sm text-gray-500">
            Ask any question. Gemini answers general topics; project context is used only when it helps.
          </p>
        )}
        {messages.map((m, i) => (
          <div key={`${m.created_at}-${i}`} className={`rounded-lg px-3 py-2 text-sm ${m.role === 'user' ? 'bg-indigo-900/40 ml-8' : 'bg-gray-800/50 mr-8'}`}>
            <p className="text-[10px] uppercase tracking-wide text-gray-500 mb-1">
              {m.role}{m.source ? ` · ${SOURCE_LABELS[m.source] || m.source}` : ''}
            </p>
            {m.role === 'assistant'
              ? <Markdown content={m.content} />
              : <p className="whitespace-pre-wrap">{m.content}</p>}
          </div>
        ))}
        <div ref={endRef} />
      </div>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); send(); }}>
        <input
          className="input-field flex-1"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask anything — security, this platform, or a general question…"
        />
        <button className="btn-primary" disabled={sending} type="submit">{sending ? 'Thinking…' : 'Send'}</button>
      </form>
    </div>
  );
}
