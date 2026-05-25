// Initialize map (Nigeria center)
var map = L.map('map').setView([9.0820, 8.6753], 6);

// Map tiles
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18
}).addTo(map);

// Airport coordinates
const airports = {
    LOS: [6.5774, 3.3211],
    ABV: [9.0068, 7.2632],
    PHC: [4.8461, 7.0109],
    KAN: [12.0476, 8.5246],
    ENU: [6.4743, 7.5619]
};

// Airport markers
for (let a in airports) {
    L.circleMarker(airports[a], {
        radius: 8,
        color: "#00ffcc",
        fillColor: "#00ffcc",
        fillOpacity: 0.8
    }).addTo(map).bindPopup(a + " Airport");
}

// Aircraft icons
let aircraftIcon = L.icon({
    iconUrl: "https://cdn-icons-png.flaticon.com/512/744/744465.png",
    iconSize: [28, 28]
});

// Simulated aircraft
let aircraft = [];
Object.values(airports).forEach((coord, i) => {
    let marker = L.marker([coord[0]+0.3, coord[1]+0.3], {icon: aircraftIcon}).addTo(map);
    aircraft.push(marker);
});

// Aircraft movement
setInterval(() => {
    aircraft.forEach(a => {
        let pos = a.getLatLng();
        a.setLatLng([pos.lat + (Math.random()-0.5)*0.05, pos.lng + (Math.random()-0.5)*0.05]);
    });
}, 3000);

// Fetch alerts + stats
function refreshDashboard() {

    fetch("http://127.0.0.1:5000/alerts")
    .then(res => res.json())
    .then(data => {
        document.getElementById("total").innerText = data.length;

        let rows = "";
        data.slice(-12).reverse().forEach(a => {
            rows += `
            <tr>
                <td>${a.timestamp}</td>
                <td>${a.airport}</td>
                <td>${a.src_ip}</td>
                <td>${a.attack_type}</td>
                <td>${a.dst_ip}</td>
                <td>${a.score}</td>
                <td>Monitoring</td>
            </tr>`;
        });
        document.getElementById("alerts").innerHTML = rows;
    });

    fetch("http://127.0.0.1:5000/stats")
    .then(res => res.json())
    .then(stats => {
        for (let k in stats) {
            document.getElementById(k).innerText = stats[k];
        }
    });
}

// Auto refresh
setInterval(refreshDashboard, 3000);
