import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [inputData, setInputData] = useState('');
  const [result, setResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/analyze', { input_data: inputData });
      setResult(response.data);
    } catch (error) {
      setResult({ error: 'Failed to analyze. Please ensure the input is valid and try again.' });
    }
  };

  return (
    <div className="App">
      <header>
        <h1>Phishing Detector</h1>
        <p>Enter a URL or IP address to check for potential phishing threats.</p>
      </header>
      <main>
        <form onSubmit={handleSubmit} className="analysis-form">
          <label htmlFor="input_data">URL or IP Address:</label>
          <input
            type="text"
            id="input_data"
            value={inputData}
            onChange={(e) => setInputData(e.target.value)}
            required
            placeholder="e.g., https://example.com or 8.8.8.8"
          />
          <button type="submit">Analyze</button>
        </form>
        {result && (
          <section className="result-section">
            <div className="result-card">
              <h2 className={`result-status ${result.result === 'Suspicious' ? 'suspicious' : result.result === 'Invalid' ? 'invalid' : 'safe'}`}>
                Result: {result.result}
              </h2>
              {result.score !== undefined && (
                <p className="result-score">
                  Confidence Score: {result.score}/100
                </p>
              )}
              {result.reasons && result.reasons.length > 0 && (
                <div className="reasons">
                  <h3>Detailed Analysis:</h3>
                  <ul>
                    {result.reasons.map((reason, index) => (
                      <li key={index}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.error && (
                <p className="error-message">{result.error}</p>
              )}
            </div>
            <p className="back-link"><a href="/">Analyze Another URL or IP</a></p>
          </section>
        )}
      </main>
      <footer>
        <p>© 2025 Phishing Detector. All rights reserved.</p>
      </footer>
    </div>
  );
}

export default App;
