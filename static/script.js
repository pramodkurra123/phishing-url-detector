async function scanURL() {

    const url = document.getElementById("urlInput").value;
    const resultBox = document.getElementById("result");
    const loading = document.getElementById("loading");

    if (!url) {
        resultBox.innerHTML = "Please enter a URL.";
        return;
    }

    loading.innerHTML = "Scanning URL...";

    try {

        const response = await fetch("/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        loading.innerHTML = "";

        if (data.error) {
            resultBox.innerHTML = data.error;
            return;
        }

        let riskList = "";

        if (data.risks && data.risks.length > 0) {

            riskList = `
                <h3>Security Analysis</h3>
                <ul>
            `;

            data.risks.forEach(function(risk) {
                riskList += `<li>${risk}</li>`;
            });

            riskList += "</ul>";

        } else {

            riskList = `
                <h3>Security Analysis</h3>
                <p>No obvious URL-based risks detected.</p>
            `;
        }

        resultBox.innerHTML = `
            <h2>Result: ${data.result}</h2>
            <p>Confidence: ${data.confidence}%</p>
            ${riskList}
        `;

        loadHistory();

    } catch (error) {

        loading.innerHTML = "";

        resultBox.innerHTML =
            "Error connecting to the server.";
    }
}


async function loadHistory() {

    const response = await fetch("/history");

    const data = await response.json();

    const history = document.getElementById("history");

    history.innerHTML = "";

    data.forEach(function(item) {

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${item.url}</td>
            <td>${item.result}</td>
            <td>${item.confidence}%</td>
            <td>${item.time}</td>
        `;

        history.appendChild(row);
    });
}


loadHistory();
