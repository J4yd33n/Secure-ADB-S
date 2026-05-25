const map = L.map('map').setView([9.0, 8.0], 6);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png')
  .addTo(map);

const airports = {
  "LOS": [6.5774, 3.3212],
  "ABV": [9.0068, 7.2632],
  "PHC": [5.0155, 6.9496],
  "KAN": [12.0476, 8.5246],
  "ENU": [6.4743, 7.5619]
};

let markers = {};

for (let code in airports) {
  markers[code] = L.marker(airports[code]).addTo(map)
    .bindPopup(code + " Airport");
}

async function updateAlerts() {
  const res = await fetch("/api/alerts");
  const data = await res.json();
  const table = document.getElementById("alertTable");
  table.innerHTML = "";

  data.forEach(a => {
    const row = table.insertRow();
    row.innerHTML = `
      <td>${a.Time}</td>
      <td>${a.Airport}</td>
      <td>${a["Attack Type"]}</td>
      <td class="${a.Severity}">${a.Severity}</td>
      <td>${a["ML Score"]}</td>
      <td><button onclick="blockIP('${a["Source IP"]}')">Block</button></td>
    `;

    if (markers[a.Airport]) {
      markers[a.Airport].setIcon(
        L.icon({
          iconUrl: 'icons/syn.png',
          iconSize: [32, 32]
        })
      );
    }
  });
}

function blockIP(ip) {
  alert("Firewall rule issued for " + ip);
}

function fakeSignals() {
  document.getElementById("signals").innerText =
    `RF Power: ${Math.random().toFixed(2)} dB\n` +
    `ADS-B Frames: ${Math.floor(Math.random()*120)}\n` +
    `ACARS Noise: ${Math.floor(Math.random()*20)}%`;
}

setInterval(updateAlerts, 2000);
setInterval(fakeSignals, 1000);
