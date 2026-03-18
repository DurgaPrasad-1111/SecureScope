import Layout from '../components/Layout'

export default function AboutPage() {
  return (
    <Layout>
      <section className="card">
        <h2>About SecureScope</h2>
        <p>SecureScope performs automated web reconnaissance and risk intelligence for authorized targets.</p>

        <h3>What Our System Scans</h3>
        <ul>
          <li><strong>Port Scan:</strong> Identifies exposed network ports and reachable services.</li>
          <li><strong>Subdomain Enumeration:</strong> Discovers publicly resolvable subdomains linked to the target.</li>
          <li><strong>DNS Record Inspection:</strong> Collects A/MX/TXT/NS records to detect DNS hygiene gaps.</li>
          <li><strong>SSL/TLS Configuration Check:</strong> Validates certificate presence and protocol strength.</li>
          <li><strong>HTTP Security Header Validation:</strong> Checks for critical headers like HSTS and CSP.</li>
          <li><strong>Technology Fingerprinting:</strong> Detects visible server/framework metadata exposure.</li>
          <li><strong>OSINT Metadata Collection:</strong> Reviews publicly exposed domain-registration metadata.</li>
          <li><strong>Cookie Flags Check:</strong> Verifies Secure, HttpOnly, and SameSite attributes on cookies.</li>
          <li><strong>Directory Enumeration:</strong> Probes common high-risk paths for unintended exposure.</li>
          <li><strong>Admin Panel Exposure Probe:</strong> Detects accessible administrative routes.</li>
          <li><strong>Rate-Limit Behavior Probe:</strong> Sends request bursts to observe throttling responses.</li>
          <li><strong>Reflected XSS Probe:</strong> Tests for reflected script payload indicators requiring manual confirmation.</li>
          <li><strong>SQLi Error Probe:</strong> Looks for SQL error pattern leakage after crafted input.</li>
          <li><strong>CSRF Token Hint Probe:</strong> Checks forms for visible anti-CSRF token indicators.</li>
        </ul>

        <p>Each scan contributes to weighted risk scoring, STRIDE classification, and remediation guidance.</p>
      </section>
    </Layout>
  )
}
