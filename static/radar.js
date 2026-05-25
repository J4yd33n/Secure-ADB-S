const canvas = document.getElementById("radar");
const ctx = canvas.getContext("2d");
const alertSound = document.getElementById("alertSound");

let angle = 0;

function drawRadar() {
  ctx.clearRect(0,0,600,600);

  ctx.beginPath();
  ctx.arc(300,300,250,0,2*Math.PI);
  ctx.strokeStyle="lime";
  ctx.stroke();

  ctx.beginPath();
  ctx.moveTo(300,300);
  ctx.lineTo(
    300 + 250*Math.cos(angle),
    300 + 250*Math.sin(angle)
  );
  ctx.stroke();

  angle += 0.02;
}

setInterval(drawRadar, 30);

async function fetchAlerts(){
  const res = await fetch("/alerts");
  const data = await res.json();
  const table = document.getElementById("alertTable");
  table.innerHTML = "";

  if(data.length > 0) alertSound.play();

  data.forEach(a=>{
    table.innerHTML += `
      <tr>
        <td>${a.timestamp}</td>
        <td>${a.attack}</td>
        <td>${a.severity}</td>
        <td>${a.ml_score}</td>
        <td>${a.response}</td>
      </tr>`;
  });
}

setInterval(fetchAlerts, 2000);
