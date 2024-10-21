fetch('/report/1')  // Replace 1 with the actual report ID
    .then(response => response.json())
    .then(data => {
        const vulnerabilitiesDiv = document.getElementById('vulnerabilities');
        data.forEach(vulnerability => {
            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = `
                <div class="card-header">${vulnerability.cve} - Severity: ${vulnerability.severity}</div>
                <div class="card-body">
                    <p><strong>Name:</strong> ${vulnerability.name}</p>
                    <p><strong>Description:</strong> ${vulnerability.description}</p>
                    <p><strong>Systems Affected:</strong> ${vulnerability.systems}</p>
                    <p><strong>Skills Required:</strong> ${vulnerability.skill}</p>
                    <p><strong>Involved Parties:</strong> ${vulnerability.parties}</p>
                    <p><strong>Estimated Cost:</strong> ${vulnerability.low_cost} - ${vulnerability.high_cost}</p>
                </div>
            `;
            vulnerabilitiesDiv.appendChild(card);
        });
    });
