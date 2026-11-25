function mostrarConsola(id, data) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  }
}

async function probarFunctionCreep() {
  const res = await fetch("/perfil/datos", {
    headers: { "X-Purpose": "marketing_terceros_no_autorizado" }
  });
  const data = await res.json();
  mostrarConsola("consolaSeguridad", { status_http: res.status, respuesta: data });
}

document.getElementById("formRectificar").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch("/perfil/rectificar", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Purpose": "perfil_propio" },
    body: JSON.stringify(payload)
  });
  mostrarConsola("consolaSeguridad", await res.json());
});

document.getElementById("formFoto").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await fetch("/perfil/foto", {
    method: "POST",
    headers: { "X-Purpose": "perfil_propio" },
    body: new FormData(e.target)
  });
  const data = await res.json();
  mostrarConsola("consolaSeguridad", data);
  if (res.ok) setTimeout(() => location.reload(), 900);
});

async function cargarMateriasProfesor() {
  const cont = document.getElementById("tablaMateriasProfesor");
  const res = await fetch("/profesor/materias", { headers: { "X-Purpose": "consulta_materias" } });
  const data = await res.json();
  if (!data.materias) return;
  let html = "<table><tr><th>ID</th><th>Clave</th><th>Materia</th></tr>";
  data.materias.forEach(m => {
    html += `<tr><td>${m.id_materia}</td><td>${m.clave_materia}</td><td>${m.nombre_materia}</td></tr>`;
  });
  html += "</table>";
  cont.innerHTML = html;
}

document.getElementById("formCalificacion").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch("/profesor/calificaciones", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Purpose": "captura_calificaciones" },
    body: JSON.stringify(payload)
  });
  mostrarConsola("consolaProfesor", await res.json());
});

document.addEventListener("DOMContentLoaded", cargarMateriasProfesor);
