import { Link } from 'react-router-dom';
import { FiActivity, FiCpu, FiLayers, FiShield, FiFileText } from 'react-icons/fi';
import { ADVANCED_LINKS } from './shared';

const COPY = {
  '/advanced/dashboard': {
    text: 'Phase 1 → 2 → 3 metrics, charts, and executive PDF.',
    icon: FiLayers,
  },
  '/advanced/integration': {
    text: 'Workflow engine, deployment gate (score 65), and project timeline.',
    icon: FiActivity,
  },
  '/advanced/assistant': {
    text: 'Google Gemini assistant for any question — this product, scans, or general topics.',
    icon: FiCpu,
  },
  '/advanced/compliance': {
    text: 'ISO 27001, NIST CSF, CIS, GDPR, HIPAA live scoring.',
    icon: FiShield,
  },
  '/advanced/forensics': {
    text: 'Hashes, chain of custody, evidence, and forensic PDF.',
    icon: FiFileText,
  },
};

export default function AdvancedHub() {
  return (
    <div className="space-y-6">
      <div className="page-hero">
        <div>
          <h1 className="font-display text-2xl font-bold">Advanced Features</h1>
          <p className="text-gray-400 mt-1">
            Enterprise layer on top of Phase 1, Phase 2, and Phase 3. Existing pages stay unchanged.
            Every tile is live. The AI assistant uses Google Gemini for any question.
          </p>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {ADVANCED_LINKS.map((link) => {
          const meta = COPY[link.to] || {};
          const Icon = meta.icon || FiLayers;
          return (
            <Link key={link.to} to={link.to} className="card hover:border-primary-500/40 hover:-translate-y-0.5 transition-all block">
              <div className="w-10 h-10 rounded-xl bg-primary-600/20 border border-primary-500/20 flex items-center justify-center mb-3">
                <Icon className="text-primary-300" />
              </div>
              <h3 className="font-semibold">{link.label}</h3>
              <p className="text-sm text-gray-500 mt-2">{meta.text}</p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
