const state = {
    refreshTimer: null
};

const els = {
    apiStatus: document.querySelector("#apiStatus"),
    apiStatusText: document.querySelector("#apiStatusText"),
    totalEvents: document.querySelector("#totalEvents"),
    criticalEvents: document.querySelector("#criticalEvents"),
    highEvents: document.querySelector("#highEvents"),
    maxRisk: document.querySelector("#maxRisk"),
    totalDevices: document.querySelector("#totalDevices"),
    mostRiskySource: document.querySelector("#mostRiskySource"),
    latestEventAt: document.querySelector("#latestEventAt"),
    lastUpdated: document.querySelector("#lastUpdated"),
    eventsBody: document.querySelector("#eventsBody"),
    devicesList: document.querySelector("#devicesList"),
    mitreBars: document.querySelector("#mitreBars"),
    refreshBtn: document.querySelector("#refreshBtn"),
    normalBtn: document.querySelector("#normalBtn"),
    cameraBtn: document.querySelector("#cameraBtn"),
    tvBtn: document.querySelector("#tvBtn"),
    clearBtn: document.querySelector("#clearBtn")
};

async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        },
        ...options
    });

    if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
    }

    if (response.status === 204) {
        return null;
    }

    const text = await response.text();
    return text ? JSON.parse(text) : null;
}

async function refresh() {
    try {
        const [report, events, devices] = await Promise.all([
            api("/api/report"),
            api("/api/events"),
            api("/api/devices")
        ]);

        renderReport(report);
        renderEvents(events);
        renderDevices(devices);
        setStatus("ok", "API online");
        els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        setStatus("down", "API unavailable");
        console.error(error);
    }
}

function renderReport(report) {
    els.totalEvents.textContent = report.totalEvents ?? 0;
    els.criticalEvents.textContent = report.criticalEvents ?? 0;
    els.highEvents.textContent = report.highEvents ?? 0;
    els.maxRisk.textContent = report.maxRiskScore ?? 0;
    els.totalDevices.textContent = report.totalDevices ?? 0;
    els.mostRiskySource.textContent = report.mostRiskySource || "none";
    els.latestEventAt.textContent = formatDate(report.latestEventAt);
    renderBars(report.eventsByMitreTactic || {});
}

function renderEvents(events) {
    if (!events || events.length === 0) {
        els.eventsBody.innerHTML = `<tr><td colspan="7" class="empty">No events yet</td></tr>`;
        return;
    }

    els.eventsBody.innerHTML = events.map((event) => {
        const severity = (event.severity || "LOW").toLowerCase();
        const target = [event.destinationIp, event.destinationPort].filter(Boolean).join(":") || "-";
        const source = [event.sourceIp, event.sourceMac].filter(Boolean).join(" / ") || "-";
        const mitre = event.mitreTactic
            ? `${escapeHtml(event.mitreTactic)}<br><span class="muted">${escapeHtml(event.mitreTechnique || "")}</span>`
            : "-";

        return `
            <tr title="${escapeHtml(event.evidence || "")}">
                <td>${formatDate(event.timestamp)}</td>
                <td><span class="badge severity-${severity}">${escapeHtml(event.severity || "LOW")}</span></td>
                <td class="risk">${event.riskScore ?? 0}</td>
                <td>${escapeHtml(event.type || "-")}<br><span class="muted">${escapeHtml(event.message || "")}</span></td>
                <td>${escapeHtml(source)}</td>
                <td>${escapeHtml(target)}</td>
                <td>${mitre}</td>
            </tr>
        `;
    }).join("");
}

function renderDevices(devices) {
    if (!devices || devices.length === 0) {
        els.devicesList.innerHTML = `<p class="empty">No devices observed</p>`;
        return;
    }

    els.devicesList.innerHTML = devices.map((device) => `
        <div class="device">
            <strong>${escapeHtml(device.vendor || "Unknown device")}</strong>
            <span>${escapeHtml(device.ip || "unknown IP")}</span>
            <span>${escapeHtml(device.mac || "unknown MAC")}</span>
        </div>
    `).join("");
}

function renderBars(groups) {
    const entries = Object.entries(groups);

    if (entries.length === 0) {
        els.mitreBars.innerHTML = `<p class="empty">No mapped tactics</p>`;
        return;
    }

    const max = Math.max(...entries.map(([, value]) => value));

    els.mitreBars.innerHTML = entries.map(([label, value]) => {
        const width = max === 0 ? 0 : Math.round((value / max) * 100);

        return `
            <div class="bar-row">
                <div class="bar-label">
                    <span>${escapeHtml(label)}</span>
                    <span>${value}</span>
                </div>
                <div class="bar-track"><div class="bar-fill" style="width: ${width}%"></div></div>
            </div>
        `;
    }).join("");
}

async function simulateNormalTraffic() {
    const observations = [
        normalObservation("192.168.0.14", "AA:BB:CC:05", "IoT Camera", "1.1.1.1", 443, "TLS", 12000, "pool.ntp.org"),
        normalObservation("192.168.0.13", "AA:BB:CC:04", "Smart TV", "8.8.8.8", 53, "UDP", 800, "time.android.com"),
        normalObservation("192.168.0.11", "AA:BB:CC:02", "iPhone", "142.250.186.14", 443, "TLS", 45000, null)
    ];

    for (const observation of observations) {
        await api("/api/observe", {
            method: "POST",
            body: JSON.stringify(observation)
        });
    }

    await refresh();
}

async function postAndRefresh(path) {
    await api(path, { method: "POST" });
    await refresh();
}

async function clearEvents() {
    await api("/api/events", { method: "DELETE" });
    await refresh();
}

function normalObservation(sourceIp, sourceMac, vendor, destinationIp, destinationPort, protocol, bytesOut, dnsQuery) {
    return {
        sourceIp,
        sourceMac,
        vendor,
        destinationIp,
        destinationPort,
        protocol,
        bytesOut,
        dnsQuery
    };
}

function setStatus(status, text) {
    els.apiStatus.className = `status-dot status-${status}`;
    els.apiStatusText.textContent = text;
}

function formatDate(value) {
    if (!value) {
        return "none";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#039;");
}

els.refreshBtn.addEventListener("click", refresh);
els.normalBtn.addEventListener("click", simulateNormalTraffic);
els.cameraBtn.addEventListener("click", () => postAndRefresh("/api/simulate/camera/exfil"));
els.tvBtn.addEventListener("click", () => postAndRefresh("/api/simulate/smart-tv/exfil"));
els.clearBtn.addEventListener("click", clearEvents);

refresh();
state.refreshTimer = window.setInterval(refresh, 5000);
