document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanForm = document.getElementById('scanForm');
    const resultContainer = document.getElementById('resultContainer');
    const loadingElement = document.getElementById('loading');
    const scanButton = document.getElementById('scanButton');
    const scanIcon = document.getElementById('scanIcon');
    const scanText = document.getElementById('scanText');

    let isResultDisplayed = false;

    const resetUI = () => {
        resultContainer.innerHTML = `<p id="defaultMessage" class="default-message">Your scan results will appear here.</p>`;
        resultContainer.className = 'result-container'; // Remove verdict class
        scanText.textContent = 'Scan';
        scanIcon.innerHTML = `<circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>`;
        isResultDisplayed = false;
    };
    
    // Listen for any changes in the input field
    urlInput.addEventListener('input', () => {
        if (isResultDisplayed) {
            resetUI();
        }
    });

    scanForm.addEventListener('submit', async (event) => {
        event.preventDefault(); 

        const url = urlInput.value.trim();

        if (isResultDisplayed) {
            urlInput.value = '';
            resetUI();
            return;
        }

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
                scanText.textContent = 'Clear';
                scanIcon.innerHTML = `<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>`;
                isResultDisplayed = true;
            } else {
                resultContainer.innerHTML = `<div class="result-verdict malicious">
                    <h3>Error</h3>
                    <p>${result.error}</p>
                </div>`;
                resultContainer.classList.add('malicious');
                isResultDisplayed = false;
            }

        } catch (error) {
            console.error('Fetch error:', error);
            loadingElement.style.display = 'none';
            resultContainer.innerHTML = `<div class="result-verdict malicious">
                <h3>Error</h3>
                <p>Could not connect to the backend server. Please make sure the Flask server is running.</p>
            </div>`;
            resultContainer.classList.add('malicious');
            isResultDisplayed = false;
        }
    });
    
    function displayResult(result) {
        let verdictClass = result.verdict.toLowerCase();
        let iconClass = 'mdi-shield-check';
        let statusText = 'This URL is safe to proceed.';

        if (verdictClass === 'malicious') {
            iconClass = 'mdi-alert-circle';
            statusText = 'This URL is not safe.';
        } else if (verdictClass === 'suspicious') {
            iconClass = 'mdi-alert';
            statusText = 'This URL is suspicious and should be treated with caution.';
        }

        let flagsCount = 0;
        if (result.reasons && result.reasons.length > 0) {
            let safeReasons = result.reasons.filter(reason => reason.includes("Domain is old and trusted") || reason.includes("URL uses a secure HTTPS connection") || reason.includes("URL uses a common TLD"));
            if (verdictClass === 'safe') {
                flagsCount = safeReasons.length;
            } else {
                 flagsCount = result.reasons.length - safeReasons.length;
            }
            if (result.reasons[0] === "No obvious suspicious signs found." || flagsCount < 0) {
                 flagsCount = 0;
            }
        }
        
        let html = `
            <div class="result-header">
                <span class="mdi ${iconClass} result-icon ${verdictClass}"></span>
                <div class="result-info">
                    <h3 class="${verdictClass}">${result.verdict}</h3>
                    <p class="${verdictClass}">${statusText}</p>
                </div>
            </div>
            <div class="result-summary">
                <div class="metric">
                    <h4>${result.score}</h4>
                    <span>Score</span>
                </div>
                <div class="metric">
                    <h4>${flagsCount}</h4>
                    <span>${(verdictClass === 'safe') ? 'Green Flag' : 'Red Flag'}${flagsCount !== 1 ? 's' : ''}</span>
                </div>
            </div>
        `;
        
        if (result.reasons && result.reasons.length > 0) {
            html += `<h4 class="reasons-header">Reasons for the Verdict:</h4>`;
            html += `<ul class="reasons-list">`;
            result.reasons.forEach(reason => {
                html += `<li>${reason}</li>`;
            });
            html += `</ul>`;
        }
        
        resultContainer.innerHTML = html;
        resultContainer.classList.add(verdictClass); // Add verdict class to the container
    }
    
    resetUI();
});
