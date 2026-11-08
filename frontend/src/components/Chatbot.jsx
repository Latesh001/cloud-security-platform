import { useEffect, useRef, useState } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import {
  FiMessageSquare, FiX, FiSend, FiTrash2, FiDownload, FiCpu,
  FiFolder, FiShield, FiActivity, FiAward, FiMinimize2, FiMaximize2,
} from 'react-icons/fi';
import api from '../services/api';
import Markdown from './Markdown';

const TABS = [
  { id: 'project', label: 'Project', icon: FiFolder, blurb: 'Architecture, workflow, and your projects' },
  { id: 'security', label: 'Security', icon: FiShield, blurb: 'Vulnerabilities, scores, and secure coding' },
  { id: 'soc', label: 'SOC', icon: FiActivity, blurb: 'Threats, AI predictions, and incident response' },
  { id: 'viva', label: 'Viva', icon: FiAward, blurb: 'Project review questions and model answers' },
];

const GREETINGS = {
  project: 'Ask me about the platform architecture, how the three phases connect, or anything about your own projects. I can also answer general questions.',
  security: 'Ask me about your security score, which findings to fix first, any vulnerability class, or any other topic.',
  soc: 'Ask me why a threat was detected, how the AI reached its confidence, what a playbook did, or any general question.',
  viva: 'I will rehearse likely project review questions and can also answer any other topic you want to practise.',
};

const SOURCE_LABELS = {
  gemini: 'Google Gemini',
  openai: 'OpenAI',
  knowledge_base: 'Knowledge base',
};

export default function Chatbot() {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [tab, setTab] = useState('security');
  const [messages, setMessages] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [projects, setProjects] = useState([]);
  const [projectId, setProjectId] = useState('');
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  const location = useLocation();
  const params = useParams();
  const scrollRef = useRef(null);
  const inputRef = useRef(null);

  // Follow the developer around the app: when they open a project page, the
  // assistant grounds its answers in that project automatically.
  useEffect(() => {
    const match = location.pathname.match(/\/projects\/(P\d+)/i);
    if (match) setProjectId(match[1]);
  }, [location.pathname, params]);

  useEffect(() => {
    if (!open) return;
    api.get('/projects')
      .then((r) => {
        const list = r.data.projects || [];
        setProjects(list);
        // Ground answers in a real project by default so replies are detailed.
        if (!projectId && list.length > 0) {
          setProjectId(list[0].project_id);
        }
      })
      .catch(() => setProjects([]));
  }, [open]);

  useEffect(() => {
    if (!open) return;
    api.get('/chatbot/suggestions', { params: { tab } })
      .then((r) => setSuggestions(r.data.suggestions || []))
      .catch(() => setSuggestions([]));
  }, [open, tab]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, sending]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 250);
  }, [open, tab]);

  const send = async (question) => {
    const text = (question ?? input).trim();
    if (!text || sending) return;

    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setInput('');
    setSending(true);

    try {
      const { data } = await api.post('/chatbot/ask', {
        question: text,
        project_id: projectId || null,
        tab,
      }, { timeout: 25000 });
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: data.answer,
        sources: data.grounded_on || [],
        provider: data.source,
      }]);
    } catch (error) {
      const timedOut = error.code === 'ECONNABORTED' || /timeout/i.test(error.message || '');
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: timedOut
          ? 'The assistant took too long on that question. Try again with a shorter question.'
          : (error.response?.data?.error
            || 'I could not reach the assistant service. Check that the backend is running and try again.'),
        isError: true,
      }]);
    } finally {
      setSending(false);
    }
  };

  const clearConversation = async () => {
    setMessages([]);
    try {
      await api.delete('/chatbot/history');
    } catch {
      // Clearing the on-screen conversation is what matters to the user.
    }
  };

  const downloadTranscript = () => {
    if (messages.length === 0) return;
    const body = messages
      .map((m) => `${m.role === 'user' ? 'You' : 'AI Security Assistant'}:\n${m.content}`)
      .join('\n\n' + '-'.repeat(60) + '\n\n');
    const header = `AI Security Assistant Transcript\nMode: ${tab}\n`
      + `Project: ${projectId || 'None'}\nExported: ${new Date().toLocaleString()}\n\n`
      + '='.repeat(60) + '\n\n';

    const url = URL.createObjectURL(new Blob([header + body], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `ai-assistant-${tab}-${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const activeTab = TABS.find((t) => t.id === tab);

  return (
    <>
      <AnimatePresence>
        {!open && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            whileHover={{ scale: 1.06 }}
            whileTap={{ scale: 0.94 }}
            onClick={() => setOpen(true)}
            className="fixed bottom-6 right-6 z-50 flex items-center gap-2 pl-4 pr-5 py-3.5 rounded-full
                       bg-gradient-to-r from-primary-600 to-accent-600 text-white shadow-2xl shadow-primary-600/40"
            aria-label="Open AI Security Assistant"
          >
            <span className="relative flex items-center justify-center">
              <FiMessageSquare className="text-xl" />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
            </span>
            <span className="text-sm font-semibold hidden sm:inline">AI Assistant</span>
          </motion.button>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.97 }}
            transition={{ duration: 0.22 }}
            className={`fixed z-50 flex flex-col bg-gray-950 border border-gray-800 rounded-2xl shadow-2xl overflow-hidden
              ${expanded
                ? 'inset-4 md:inset-10'
                : 'bottom-4 right-4 left-4 sm:left-auto sm:w-[440px] h-[min(680px,calc(100vh-2rem))]'}`}
          >
            {/* Header */}
            <div className="px-4 py-3 bg-gradient-to-r from-primary-600/20 to-accent-600/20 border-b border-gray-800 flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shrink-0">
                <FiCpu className="text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-sm leading-tight">AI Security Assistant</p>
                <p className="text-xs text-gray-500 truncate">{activeTab?.blurb}</p>
              </div>
              <button onClick={() => setExpanded((v) => !v)}
                className="hidden sm:block p-2 text-gray-400 hover:text-gray-200 rounded-lg hover:bg-gray-800/60"
                title={expanded ? 'Restore size' : 'Expand'}>
                {expanded ? <FiMinimize2 /> : <FiMaximize2 />}
              </button>
              <button onClick={() => setOpen(false)}
                className="p-2 text-gray-400 hover:text-gray-200 rounded-lg hover:bg-gray-800/60" title="Close">
                <FiX />
              </button>
            </div>

            {/* Mode tabs */}
            <div className="flex border-b border-gray-800 bg-gray-900/50">
              {TABS.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setTab(id)}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors border-b-2
                    ${tab === id
                      ? 'border-primary-500 text-primary-400 bg-primary-600/10'
                      : 'border-transparent text-gray-500 hover:text-gray-300'}`}
                >
                  <Icon className="text-sm" />
                  {label}
                </button>
              ))}
            </div>

            {/* Project context selector */}
            <div className="px-4 py-2.5 border-b border-gray-800 flex items-center gap-2 bg-gray-900/30">
              <label htmlFor="assistant-project" className="text-xs text-gray-500 shrink-0">Context</label>
              <select
                id="assistant-project"
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                className="flex-1 bg-gray-800/60 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs
                           text-gray-200 focus:outline-none focus:ring-1 focus:ring-primary-500 min-w-0"
              >
                <option value="">No project (general questions)</option>
                {projects.map((p) => (
                  <option key={p.project_id} value={p.project_id}>
                    {p.project_id} — {p.project_name}
                  </option>
                ))}
              </select>
            </div>

            {/* Conversation */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
              {messages.length === 0 && (
                <div className="space-y-4">
                  <div className="bg-gray-900/70 border border-gray-800 rounded-xl p-4">
                    <p className="text-sm text-gray-300 leading-relaxed">{GREETINGS[tab]}</p>
                    {!projectId && (
                      <p className="text-xs text-gray-500 mt-2">
                        Select a project above and I will ground my answers in your own scan results.
                      </p>
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-medium text-gray-500 mb-2 uppercase tracking-wide">
                      Suggested questions
                    </p>
                    <div className="space-y-2">
                      {suggestions.map((question) => (
                        <button
                          key={question}
                          onClick={() => send(question)}
                          className="w-full text-left text-sm px-3 py-2.5 rounded-lg bg-gray-900/60 border border-gray-800
                                     text-gray-300 hover:border-primary-500/40 hover:text-primary-300 hover:bg-primary-600/5
                                     transition-colors"
                        >
                          {question}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {messages.map((message, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={message.role === 'user' ? 'flex justify-end' : ''}
                >
                  {message.role === 'user' ? (
                    <div className="max-w-[85%] bg-primary-600 text-white rounded-2xl rounded-br-sm px-4 py-2.5 text-sm">
                      {message.content}
                    </div>
                  ) : (
                    <div className={`rounded-2xl rounded-bl-sm px-4 py-3 border
                      ${message.isError
                        ? 'bg-red-500/10 border-red-500/30'
                        : 'bg-gray-900/70 border-gray-800'}`}>
                      <Markdown content={message.content} />
                      {(message.provider || message.sources?.length > 0) && (
                        <div className="flex flex-wrap gap-1.5 mt-3 pt-3 border-t border-gray-800">
                          {message.provider && (
                            <span className="text-[10px] px-2 py-0.5 rounded-full bg-primary-600/15 text-primary-300 border border-primary-500/30">
                              {SOURCE_LABELS[message.provider] || message.provider}
                            </span>
                          )}
                          {message.sources?.map((source) => (
                            <span key={source}
                              className="text-[10px] px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 border border-gray-700">
                              {source}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </motion.div>
              ))}

              {sending && (
                <div className="bg-gray-900/70 border border-gray-800 rounded-2xl rounded-bl-sm px-4 py-3 w-fit">
                  <div className="flex gap-1.5">
                    {[0, 1, 2].map((i) => (
                      <span key={i}
                        className="w-2 h-2 rounded-full bg-primary-400 animate-bounce"
                        style={{ animationDelay: `${i * 0.15}s` }} />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Composer */}
            <div className="border-t border-gray-800 p-3 bg-gray-900/40">
              <div className="flex items-end gap-2">
                <textarea
                  ref={inputRef}
                  rows={1}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      send();
                    }
                  }}
                  placeholder="Ask about your project, a vulnerability, or an incident..."
                  className="flex-1 resize-none max-h-28 bg-gray-800/60 border border-gray-700 rounded-xl px-3.5 py-2.5
                             text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
                <button
                  onClick={() => send()}
                  disabled={!input.trim() || sending}
                  className="p-2.5 rounded-xl bg-gradient-to-r from-primary-600 to-accent-600 text-white
                             disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity"
                  title="Send message"
                >
                  <FiSend />
                </button>
              </div>

              <div className="flex items-center justify-between mt-2 px-1">
                <p className="text-[10px] text-gray-600">Enter to send · Shift+Enter for a new line</p>
                <div className="flex gap-1">
                  <button onClick={downloadTranscript} disabled={messages.length === 0}
                    className="p-1.5 text-gray-500 hover:text-gray-300 disabled:opacity-30 rounded"
                    title="Download transcript">
                    <FiDownload className="text-sm" />
                  </button>
                  <button onClick={clearConversation} disabled={messages.length === 0}
                    className="p-1.5 text-gray-500 hover:text-red-400 disabled:opacity-30 rounded"
                    title="Clear conversation">
                    <FiTrash2 className="text-sm" />
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
