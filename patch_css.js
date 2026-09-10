const fs = require('fs');
let css = fs.readFileSync('frontend/index.css', 'utf8');

const newCSS = `
/* Real-Time Toast Alerts */
.toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  z-index: 9999;
}
.toast {
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 4px solid var(--accent);
  padding: 16px;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  color: var(--text);
  min-width: 300px;
  max-width: 400px;
  animation: slideIn 0.3s ease-out forwards;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.toast.toast-high { border-left-color: #ff8a4c; }
.toast.toast-critical { border-left-color: #ff5c5c; }
.toast.toast-low { border-left-color: #3ecf8e; }
.toast.toast-medium { border-left-color: #f5b942; }
.toast-title { font-weight: 600; font-size: 14px; }
.toast-msg { font-size: 13px; color: var(--muted); }
@keyframes slideIn {
  from { transform: translateX(120%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
@keyframes slideOut {
  from { transform: translateX(0); opacity: 1; }
  to { transform: translateX(120%); opacity: 0; }
}

/* Visual Trace Map (Node Graph) */
.relay-graph {
  position: relative;
  padding-left: 28px;
  margin-top: 14px;
  margin-bottom: 10px;
}
.relay-graph::before {
  content: "";
  position: absolute;
  left: 11px;
  top: 12px;
  bottom: 24px;
  width: 2px;
  background: var(--border);
  z-index: 0;
}
.relay-node {
  position: relative;
  margin-bottom: 20px;
  z-index: 1;
}
.relay-node:last-child {
  margin-bottom: 0;
}
.relay-dot {
  position: absolute;
  left: -28px;
  top: 6px;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: var(--card-bg);
  border: 2px solid var(--accent);
  z-index: 2;
}
.relay-dot.external {
  border-color: #ff8a4c;
  background: rgba(255,138,76, 0.2);
}
.relay-dot.internal {
  border-color: #5b8cff;
  background: rgba(91,140,255, 0.2);
}
.relay-content {
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  font-size: 13px;
}
.relay-title {
  font-weight: 600;
  color: var(--text);
  margin-bottom: 6px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.relay-subtitle {
  color: var(--muted);
  font-size: 11.5px;
  line-height: 1.4;
}
`;
fs.writeFileSync('frontend/index.css', css + newCSS);
console.log('patched css');
