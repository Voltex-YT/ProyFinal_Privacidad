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
  cargarTelemetriaSIEM();
}

async function simularFuerzaBruta() {
  mostrarConsola("consolaAlertasSIEM", "Enviando 5 intentos fallidos de autenticacion...");
  for (let i = 1; i <= 5; i++) {
    await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ matricula: "202448106", password: "ClaveIncorrecta_" + i })
    });
  }
  setTimeout(cargarTelemetriaSIEM, 400);
}

async function cargarTelemetriaSIEM() {
  const res = await fetch("/admin/telemetria-siem", {
    headers: { "X-Purpose": "auditoria_arco" }
  });
  if (!res.ok) return;
  const data = await res.json();
  mostrarConsola("consolaAlertasSIEM", data.siem_alertas_correlacion.length ? data.siem_alertas_correlacion : "Sin alertas criticas aun (0)");
  mostrarConsola("consolaLogsSIEM", data.siem_eventos_rfc5424.join("\n"));
  mostrarConsola("consolaSegregacionBD", data.bd_academia_sin_pii);
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

document.getElementById("formNuevoUsuario").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch("/admin/usuarios", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Purpose": "gestion_usuarios" },
    body: JSON.stringify(payload)
  });
  mostrarConsola("consolaPrivacidad", await res.json());
  cargarTelemetriaSIEM();
});

document.getElementById("formNuevaMateria").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  const res = await fetch("/admin/materias", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Purpose": "gestion_usuarios" },
    body: JSON.stringify(payload)
  });
  mostrarConsola("consolaPrivacidad", await res.json());
});

async function cargarUsuariosAdmin() {
  const res = await fetch("/admin/usuarios", { headers: { "X-Purpose": "gestion_usuarios" } });
  mostrarConsola("consolaPrivacidad", await res.json());
  cargarTelemetriaSIEM();
}

async function exportarSafeHarbor() {
  const res = await fetch("/admin/exportar-estadisticas", { headers: { "X-Purpose": "exportacion_estadistica" } });
  mostrarConsola("consolaPrivacidad", await res.json());
  cargarTelemetriaSIEM();
}

async function cargarBitacoraARCO() {
  const res = await fetch("/admin/bitacora-arco", { headers: { "X-Purpose": "auditoria_arco" } });
  mostrarConsola("consolaPrivacidad", await res.json());
}

document.addEventListener("DOMContentLoaded", cargarTelemetriaSIEM);
