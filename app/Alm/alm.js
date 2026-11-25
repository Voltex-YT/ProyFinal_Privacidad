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

async function ejecutarSupresionARCO() {
  if (!confirm("Esta accion sobrescribira y eliminara permanentemente tus datos PII y academicos bajo NIST SP 800-88, y cerrara tu sesion. Continuar?")) {
    return;
  }
  const res = await fetch("/perfil/arco/supresion", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Purpose": "ejercicio_arco" },
    body: JSON.stringify({ purpose: "ejercicio_arco" })
  });
  const data = await res.json();
  mostrarConsola("consolaSeguridad", data);
  if (data.certificado && data.certificado.id_certificado) {
    const id = data.certificado.id_certificado;
    document.getElementById("descargasCertificado").innerHTML = `
      <div style="margin-top:0.85rem; padding:0.75rem; background:#fef2f2; border:1px solid #fecaca; border-radius:8px; color:#991b1b; font-size:0.85rem; font-weight:600;">
        Identidad purgada y sesion cerrada. Descargando certificado y redirigiendo al inicio de sesion...
      </div>
    `;
    window.location.href = `/perfil/arco/certificado/${id}/pdf`;
    setTimeout(() => {
      window.location.replace("/login");
    }, 2500);
  }
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

async function cargarKardexAlumno() {
  const cont = document.getElementById("tablaKardexAlumno");
  const res = await fetch("/alumno/kardex", { headers: { "X-Purpose": "consulta_kardex" } });
  const data = await res.json();
  if (!data.kardex) return;
  let html = "<table><tr><th>Clave</th><th>Materia</th><th>Calificacion</th><th>Fecha</th></tr>";
  data.kardex.forEach(k => {
    html += `<tr><td>${k.clave_materia}</td><td>${k.nombre_materia}</td><td>${k.calificacion}</td><td>${k.fecha_registro}</td></tr>`;
  });
  html += "</table>";
  cont.innerHTML = html;
}

document.addEventListener("DOMContentLoaded", cargarKardexAlumno);
