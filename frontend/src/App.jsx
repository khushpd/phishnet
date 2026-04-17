import { useState } from "react";
import axios from "axios";

function App() {
  const [inputText, setInputText] = useState("");
  const [sender, setSender] = useState("");
  const [result, setResult] = useState(null);

  const analyzeEmail = async () => {
    try {
      const res = await axios.post("http://127.0.0.1:8000/api/analyze/email", {
        text: inputText,
        sender: sender
      });

      setResult(res.data);
    } catch (error) {
      console.error("Error:", error);
    }
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1>Email Analyzer</h1>

      {/* Sender */}
      <input
        type="text"
        placeholder="Enter sender email"
        value={sender}
        onChange={(e) => setSender(e.target.value)}
        style={{ width: "400px", marginBottom: "10px" }}
      />

      <br />

      {/* Email Text */}
      <textarea
        rows="6"
        cols="60"
        placeholder="Paste email here"
        value={inputText}
        onChange={(e) => setInputText(e.target.value)}
      />

      <br /><br />

      <button onClick={analyzeEmail}>Analyze</button>

      {/* Results */}
      {result && (
        <div style={{ marginTop: "20px" }}>
          <h3>Risk Score: {result.risk_score}</h3>
          <h4>Level: {result.risk_level}</h4>

          <h3>Text Indicators:</h3>
          <ul>
            {result.indicators.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>

          <h3>Sender Analysis:</h3>
          <ul>
            {result.sender_flags.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>

          <h3>URLs Found:</h3>
          <ul>
            {result.urls_found.map((url, index) => (
              <li key={index}>{url}</li>
            ))}
          </ul>

          <h3>URL Analysis:</h3>
          <ul>
            {result.url_flags.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;