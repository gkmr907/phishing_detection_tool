document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanForm = document.getElementById('scanForm');
    const resultContainer = document.getElementById('resultContainer');
    const loadingElement = document.getElementById('loading');

    scanForm.addEventListener('submit', async (event) => {
        event.preventDefault(); 
        
        const url = urlInput.value.trim();

        if (url === "") {
            alert("Please enter a URL to scan.");
            return;
        }
        
        resultContainer.innerHTML = '';
        loadingElement.style.display = 'flex';
        
        try {
            const response = await fetch('http://127.0.0.1:5000/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            const result = await response.json();

            loadingElement.style.display = 'none';

            if (response.ok) {
                displayResult(result);
            } else {
                resultContainer.innerHTML = `<div class="result-verdict malicious">
                    <h3>Error</h3>
                    <p>${result.error}</p>
                </div>`;
            }

        } catch (error) {
            console.error('Fetch error:', error);
            loadingElement.style.display = 'none';
            resultContainer.innerHTML = `<div class="result-verdict malicious">
                <h3>Error</h3>
                <p>Could not connect to the backend server. Please make sure the Flask server is running.</p>
            </div>`;
        }
    });
    
    function displayResult(result) {
        let verdictClass = result.verdict.toLowerCase();
        let html = `
            <div class="result-verdict ${verdictClass}">
                <div class="result-verdict-info">
                    <h3>Verdict: ${result.verdict}</h3>
                    <p>Suspicion Score: ${result.score}</p>
                </div>
                <div class="info-icon-container">
                    <span class="info-icon">ⓘ</span>
                    <div class="info-tooltip">
                        <p><strong>Scoring Guide:</strong></p>
                        <ul>
                            <li><strong>Safe:</strong> Score is 0</li>
                            <li><strong>Suspicious:</strong> Score is 1-59</li>
                            <li><strong>Malicious:</strong> Score is 60+</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
        
        if (result.reasons && result.reasons.length > 0) {
            html += `<p class="reasons-header">**Reasons for Verdict:**</p>`;
            html += `<ul class="reasons-list">`;
            result.reasons.forEach(reason => {
                html += `<li>${reason}</li>`;
            });
            html += `</ul>`;
        }
        
        resultContainer.innerHTML = html;
    }
});
