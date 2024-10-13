console.log("Popup script started");

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM content loaded");

    const exportButton = document.getElementById('export-logs');

    console.log("Export button:", exportButton);

    exportButton.addEventListener('click', function() {
        console.log("Export logs button clicked");
        chrome.runtime.sendMessage({action: "exportLogs"}, function(response) {
            console.log("Received export logs response:", response);
            if (response && response.logs && response.logs.length > 0) {
                const blob = new Blob([JSON.stringify(response.logs, null, 2)], {type: "application/json"});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'smuggleshield_logs.json';
                a.style.display = 'none';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } else {
                alert('No logs available to export.');
            }
        });
    });
});
