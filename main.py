from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def web_panel():
    return """
    <html>
    <head>
        <title>Camlock Control Panel</title>
    </head>
    <body>
        <h1>Camlock Control</h1>
        <button onclick="toggle(true)">Turn ON</button>
        <button onclick="toggle(false)">Turn OFF</button>
        <p id="status">Loading...</p>

        <script>
            const API_URL = '/api/status';
            const API_KEY = 'test_key_123';

            async function updateStatus() {
                try {
                    const res = await fetch(API_URL, {
                        headers: { 'Authorization': API_KEY }
                    });
                    const data = await res.json();
                    document.getElementById('status').innerText =
                        'Camlock is ' + (data.camlock ? 'ON' : 'OFF');
                } catch (err) {
                    document.getElementById('status').innerText = 'Error fetching status';
                }
            }

            async function toggle(state) {
                try {
                    await fetch(API_URL, {
                        method: 'POST',
                        headers: {
                            'Authorization': API_KEY,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ camlock: state })
                    });
                    updateStatus();
                } catch (err) {
                    alert('Failed to toggle state');
                }
            }

            setInterval(updateStatus, 2000); // update every 2 seconds
            updateStatus();
        </script>
    </body>
    </html>
    """
