import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import { motion } from 'framer-motion';
import {
  FiUploadCloud, FiFile, FiCheckCircle, FiAlertTriangle, FiArrowLeft,
  FiSearch, FiShield, FiX,
} from 'react-icons/fi';
import api from '../services/api';
import { Alert, PageHeader, ScoreRing } from '../components/ui';

const LANGUAGES = ['Python', 'Java', 'JavaScript', 'TypeScript', 'PHP', 'C#', 'Go', 'Ruby', 'Other'];
const FRAMEWORKS = ['Flask', 'Django', 'Spring Boot', 'Express', 'React', 'Angular', 'Vue',
  'Laravel', 'ASP.NET', '.NET Core', 'Node.js', 'Other'];
const CLOUD_PROVIDERS = ['AWS', 'Azure', 'Google Cloud', 'On-Premise', 'Not Deployed Yet'];

const MAX_SIZE_MB = 1000;
const UPLOAD_TIMEOUT_MS = 30 * 60 * 1000;

const detailsSchema = Yup.object({
  project_name: Yup.string().trim().min(3, 'At least 3 characters').max(200).required('Project name is required'),
  description: Yup.string().max(2000, 'Description is too long'),
  category: Yup.string().required('Select a category'),
  programming_language: Yup.string().required('Select the primary language'),
  framework: Yup.string().required('Select the framework'),
  version: Yup.string().max(50),
  cloud_provider: Yup.string().required('Select a target environment'),
});

const STEPS = [
  { id: 1, label: 'Project Details' },
  { id: 2, label: 'Upload Source' },
  { id: 3, label: 'Assessment Result' },
];

function StepIndicator({ current }) {
  return (
    <div className="flex items-center justify-center gap-2 sm:gap-4">
      {STEPS.map((step, index) => (
        <div key={step.id} className="flex items-center gap-2 sm:gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold transition-colors
              ${current > step.id ? 'bg-success-600 text-white'
                : current === step.id ? 'bg-primary-600 text-white'
                : 'bg-gray-800 text-gray-500'}`}>
              {current > step.id ? <FiCheckCircle /> : step.id}
            </div>
            <span className={`text-sm hidden sm:inline ${current >= step.id ? 'text-gray-200' : 'text-gray-600'}`}>
              {step.label}
            </span>
          </div>
          {index < STEPS.length - 1 && (
            <div className={`w-8 sm:w-12 h-0.5 ${current > step.id ? 'bg-success-600' : 'bg-gray-800'}`} />
          )}
        </div>
      ))}
    </div>
  );
}

export default function CreateProject() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [categories, setCategories] = useState([]);
  const [project, setProject] = useState(null);
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  useEffect(() => {
    api.get('/projects/categories')
      .then((r) => setCategories(r.data.categories || []))
      .catch(() => setCategories(['General Software']));
  }, []);

  const createProject = async (values, { setSubmitting }) => {
    setError('');
    try {
      const { data } = await api.post('/projects/create', values);
      setProject(data.project);
      setStep(2);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not create the project. Please try again.');
    }
    setSubmitting(false);
  };

  const validateFile = (candidate) => {
    if (!candidate) return 'No file selected.';
    if (!candidate.name.toLowerCase().endsWith('.zip')) return 'Only ZIP archives are accepted.';
    if (candidate.size === 0) return 'The selected file is empty.';
    if (candidate.size > MAX_SIZE_MB * 1024 * 1024) return `The archive exceeds the ${MAX_SIZE_MB} MB limit.`;
    return '';
  };

  const selectFile = (candidate) => {
    const message = validateFile(candidate);
    if (message) {
      setError(message);
      setFile(null);
      return;
    }
    setError('');
    setFile(candidate);
  };

  const uploadAndScan = async () => {
    if (!file || !project) return;
    setError('');
    setScanning(true);
    setUploadProgress(0);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const { data } = await api.post(`/projects/upload/${project.project_id}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: UPLOAD_TIMEOUT_MS,
        onUploadProgress: (event) => {
          if (event.total) {
            setUploadProgress(Math.round((event.loaded * 100) / event.total));
          }
        },
      });

      if (data.scan?.error) {
        setError(data.scan.error);
        setScanning(false);
        return;
      }

      setScanResult(data.scan);
      setStep(3);
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed. Confirm the backend is running and try again.');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <PageHeader
        title="New Project"
        subtitle="Create a project, upload your source archive, and run the Phase 1 security assessment"
      >
        <button onClick={() => navigate('/projects')} className="btn-secondary flex items-center gap-2">
          <FiArrowLeft /> Back
        </button>
      </PageHeader>

      <div className="card">
        <StepIndicator current={step} />
      </div>

      {error && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Alert type="error">
            <div className="flex items-start gap-2">
              <FiAlertTriangle className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          </Alert>
        </motion.div>
      )}

      {/* Step 1 — project details */}
      {step === 1 && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="card">
          <Formik
            initialValues={{
              project_name: '', description: '', category: '',
              programming_language: '', framework: '', version: '1.0.0', cloud_provider: '',
            }}
            validationSchema={detailsSchema}
            onSubmit={createProject}
          >
            {({ isSubmitting }) => (
              <Form className="space-y-5">
                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Project Name</label>
                  <Field name="project_name" placeholder="e.g. Hospital Management System" className="input-field" />
                  <ErrorMessage name="project_name" component="p" className="text-red-400 text-xs mt-1" />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Description</label>
                  <Field as="textarea" name="description" rows={3}
                    placeholder="What does this application do, and who uses it?"
                    className="input-field resize-none" />
                  <ErrorMessage name="description" component="p" className="text-red-400 text-xs mt-1" />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Project Category</label>
                  <Field as="select" name="category" className="input-field">
                    <option value="">Select a category</option>
                    {categories.map((c) => <option key={c} value={c}>{c}</option>)}
                  </Field>
                  <ErrorMessage name="category" component="p" className="text-red-400 text-xs mt-1" />
                  <p className="text-xs text-gray-500 mt-2 leading-relaxed">
                    The category is an input to the assessment engine, not just a label. A financial or
                    healthcare application escalates the severity and scoring weight of credential,
                    encryption, and access-control findings compared with general software.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Primary Language</label>
                    <Field as="select" name="programming_language" className="input-field">
                      <option value="">Select</option>
                      {LANGUAGES.map((l) => <option key={l} value={l}>{l}</option>)}
                    </Field>
                    <ErrorMessage name="programming_language" component="p" className="text-red-400 text-xs mt-1" />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Framework</label>
                    <Field as="select" name="framework" className="input-field">
                      <option value="">Select</option>
                      {FRAMEWORKS.map((f) => <option key={f} value={f}>{f}</option>)}
                    </Field>
                    <ErrorMessage name="framework" component="p" className="text-red-400 text-xs mt-1" />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Version</label>
                    <Field name="version" placeholder="1.0.0" className="input-field" />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Target Environment</label>
                    <Field as="select" name="cloud_provider" className="input-field">
                      <option value="">Select</option>
                      {CLOUD_PROVIDERS.map((p) => <option key={p} value={p}>{p}</option>)}
                    </Field>
                    <ErrorMessage name="cloud_provider" component="p" className="text-red-400 text-xs mt-1" />
                  </div>
                </div>

                <button type="submit" disabled={isSubmitting} className="btn-primary w-full">
                  {isSubmitting ? 'Creating Project...' : 'Continue to Upload'}
                </button>
              </Form>
            )}
          </Formik>
        </motion.div>
      )}

      {/* Step 2 — upload */}
      {step === 2 && project && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <div className="card">
            <div className="flex items-center justify-between flex-wrap gap-3 mb-5">
              <div>
                <h3 className="font-semibold">{project.project_name}</h3>
                <p className="text-sm text-gray-500">{project.project_id} · {project.category}</p>
              </div>
              <span className="text-xs text-gray-500">Maximum {MAX_SIZE_MB} MB · ZIP only</span>
            </div>

            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                selectFile(e.dataTransfer.files?.[0]);
              }}
              onClick={() => !scanning && fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors
                ${dragging ? 'border-primary-500 bg-primary-600/10' : 'border-gray-700 hover:border-gray-600'}
                ${scanning ? 'pointer-events-none opacity-60' : ''}`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip,application/zip"
                className="hidden"
                onChange={(e) => selectFile(e.target.files?.[0])}
              />
              {file ? (
                <div className="flex items-center justify-center gap-3">
                  <FiFile className="text-3xl text-primary-400" />
                  <div className="text-left">
                    <p className="font-medium text-sm">{file.name}</p>
                    <p className="text-xs text-gray-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                  </div>
                  {!scanning && (
                    <button
                      onClick={(e) => { e.stopPropagation(); setFile(null); }}
                      className="p-1.5 text-gray-500 hover:text-red-400 rounded"
                      title="Remove file"
                    >
                      <FiX />
                    </button>
                  )}
                </div>
              ) : (
                <>
                  <FiUploadCloud className="text-4xl text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-300 font-medium">Drop your project ZIP here</p>
                  <p className="text-sm text-gray-500 mt-1">or click to browse</p>
                </>
              )}
            </div>

            {scanning && (
              <div className="mt-5 space-y-3">
                <div>
                  <div className="flex justify-between text-xs text-gray-500 mb-1.5">
                    <span>{uploadProgress < 100 ? 'Uploading archive' : 'Upload complete'}</span>
                    <span>{uploadProgress}%</span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-gradient-to-r from-primary-500 to-accent-500"
                      animate={{ width: `${uploadProgress}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                </div>

                {uploadProgress === 100 && (
                  <div className="flex items-center gap-3 p-4 bg-gray-800/50 rounded-lg">
                    <FiSearch className="text-primary-400 animate-pulse text-xl shrink-0" />
                    <div>
                      <p className="text-sm font-medium">Running Phase 1 security assessment</p>
                      <p className="text-xs text-gray-500">
                        Scanning for secrets, insecure code, misconfigurations, IaC issues, and vulnerable dependencies.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="flex gap-3 mt-6">
              <button onClick={() => setStep(1)} disabled={scanning} className="btn-secondary">
                Back
              </button>
              <button onClick={uploadAndScan} disabled={!file || scanning} className="btn-primary flex-1">
                {scanning ? 'Scanning...' : 'Upload and Start Assessment'}
              </button>
            </div>
          </div>

          <div className="card">
            <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
              <FiShield className="text-primary-400" /> What the assessment checks
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm text-gray-400">
              {[
                'Hardcoded secrets, API keys, and private keys',
                'Injection, XSS, and insecure deserialization',
                'Debug flags and weak configuration defaults',
                'Terraform, Docker, and Kubernetes misconfigurations',
                'Dependencies with known CVEs',
                'Category-specific compliance risk weighting',
              ].map((item) => (
                <div key={item} className="flex gap-2">
                  <span className="text-primary-400 shrink-0">•</span>{item}
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* Step 3 — result */}
      {step === 3 && scanResult && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <div className="card text-center">
            <ScoreRing score={scanResult.score} />
            <h3 className="text-xl font-bold mt-4">
              {scanResult.approval_status === 'Approved' ? 'Project Approved' : 'Remediation Required'}
            </h3>
            <p className="text-gray-500 text-sm mt-1 max-w-lg mx-auto">
              {scanResult.approval_status === 'Approved'
                ? 'The project scored at or above 65, so cloud security monitoring is now enabled.'
                : 'Approval requires a score of at least 65. Fix the issues below and rescan.'}
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
              {[
                ['Critical', scanResult.counts?.Critical ?? 0, 'text-red-400'],
                ['High', scanResult.counts?.High ?? 0, 'text-orange-400'],
                ['Medium', scanResult.counts?.Medium ?? 0, 'text-yellow-400'],
                ['Low', scanResult.counts?.Low ?? 0, 'text-blue-400'],
              ].map(([label, value, color]) => (
                <div key={label} className="bg-gray-800/50 rounded-lg py-3">
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-gray-500">{label}</p>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap justify-center gap-4 mt-5 text-xs text-gray-500">
              <span>{scanResult.files_scanned} files scanned</span>
              <span>·</span>
              <span>{scanResult.scan_duration}s scan time</span>
              <span>·</span>
              <span>Risk level: {scanResult.risk_level}</span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <button onClick={() => navigate(`/projects/${project.project_id}`)} className="btn-primary flex-1">
              View Full Report
            </button>
            <button onClick={() => navigate('/projects')} className="btn-secondary">
              All Projects
            </button>
          </div>
        </motion.div>
      )}
    </div>
  );
}
