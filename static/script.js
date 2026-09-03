// ============================================================
// CYBERSHIELD
// Frontend JavaScript
// ============================================================


let selectedFile = null;


// ============================================================
// PAGE LOAD
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const fileInput =
            document.getElementById("emailFile");

        if (fileInput) {

            fileInput.addEventListener(
                "change",
                function () {

                    if (this.files && this.files.length > 0) {

                        selectedFile =
                            this.files[0];

                        setStatus(
                            "Selected: " +
                            selectedFile.name,
                            false
                        );

                    } else {

                        selectedFile = null;

                        setStatus(
                            "",
                            false
                        );

                    }

                }
            );

        }

    }
);


// ============================================================
// STATUS MESSAGE
// ============================================================

function setStatus(
    message,
    isError = false
) {

    const status =
        document.getElementById(
            "statusMessage"
        );

    if (!status) {
        return;
    }

    status.textContent =
        message;

    status.style.display =
        message ? "block" : "none";

    status.style.color =
        isError
            ? "#a52e2e"
            : "#475467";

}


// ============================================================
// ANALYZE UPLOADED EMAIL
// ============================================================

async function analyzeEmail() {

    const fileInput =
        document.getElementById(
            "emailFile"
        );

    const analyzeButton =
        document.getElementById(
            "analyzeBtn"
        );

    if (
        !fileInput ||
        !fileInput.files ||
        fileInput.files.length === 0
    ) {

        alert(
            "Please choose an .eml or .txt file first."
        );

        return;

    }


    selectedFile =
        fileInput.files[0];


    const formData =
        new FormData();

    formData.append(
        "file",
        selectedFile
    );


    if (analyzeButton) {

        analyzeButton.disabled =
            true;

    }


    setStatus(
        "Analyzing email...",
        false
    );


    try {

        const response =
            await fetch(
                "/api/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );


        const data =
            await response.json();


        if (!response.ok || data.success === false) {

            throw new Error(
                data.error ||
                "Unable to analyze the email."
            );

        }


        displayResult(
            data
        );


        setStatus(
            "Analysis completed successfully.",
            false
        );


    } catch (error) {

        console.error(
            "Analysis error:",
            error
        );

        alert(
            "Analysis error: " +
            error.message
        );

        setStatus(
            "Analysis failed.",
            true
        );


    } finally {

        if (analyzeButton) {

            analyzeButton.disabled =
                false;

        }

    }

}


// ============================================================
// RUN DEMO
// ============================================================

async function runDemo() {

    const demoButton =
        document.getElementById(
            "demoBtn"
        );


    if (demoButton) {

        demoButton.disabled =
            true;

    }


    setStatus(
        "Loading CyberShield demo...",
        false
    );


    try {

        const response =
            await fetch(
                "/api/demo",
                {
                    method: "POST"
                }
            );


        const data =
            await response.json();


        if (!response.ok || data.success === false) {

            throw new Error(
                data.error ||
                "Demo could not be loaded."
            );

        }


        displayResult(
            data
        );


        setStatus(
            "Demo loaded successfully.",
            false
        );


        // Scroll to the results

        const results =
            document.getElementById(
                "results"
            );

        if (results) {

            setTimeout(
                function () {

                    results.scrollIntoView({
                        behavior: "smooth",
                        block: "start"
                    });

                },
                150
            );

        }


    } catch (error) {

        console.error(
            "Demo error:",
            error
        );

        alert(
            "Demo error: " +
            error.message
        );


        setStatus(
            "Demo failed.",
            true
        );


    } finally {

        if (demoButton) {

            demoButton.disabled =
                false;

        }

    }

}


// ============================================================
// DISPLAY RESULT
// ============================================================

function displayResult(data) {

    // --------------------------------------------------------
    // Safe defaults
    // --------------------------------------------------------

    const infrastructure =
        data.infrastructure || {};

    const authentication =
        data.authentication || {};

    const indicators =
        data.indicators || {};

    const forensic =
        data.forensic || {};


    // --------------------------------------------------------
    // TOP CARDS
    // --------------------------------------------------------

    setText(
        "threatValue",
        data.threat || "—"
    );


    const risk =
        Number(
            data.risk_score || 0
        );


    setText(
        "riskScore",
        risk + "/100"
    );


    const riskBar =
        document.getElementById(
            "riskBar"
        );

    if (riskBar) {

        riskBar.style.width =
            Math.max(
                0,
                Math.min(
                    100,
                    risk
                )
            ) + "%";

    }


    setText(
        "iocValue",
        data.iocs ?? 0
    );


    setText(
        "evidenceValue",
        data.evidence || "—"
    );


    // --------------------------------------------------------
    // WHY SUSPICIOUS
    // --------------------------------------------------------

    const reasons =
        data.why_suspicious ||
        data.reasons ||
        [];


    const whyBox =
        document.getElementById(
            "whySuspicious"
        );


    if (whyBox) {

        if (
            Array.isArray(reasons) &&
            reasons.length > 0
        ) {

            whyBox.innerHTML =
                reasons
                    .map(
                        reason =>
                            `<div class="reason-item">• ${escapeHTML(reason)}</div>`
                    )
                    .join("");

        } else {

            whyBox.innerHTML =
                `<div class="reason-item">
                    No major suspicious indicators detected.
                 </div>`;

        }

    }


    // --------------------------------------------------------
    // INFRASTRUCTURE
    // --------------------------------------------------------

    setText(
        "countryValue",
        infrastructure.country || "—"
    );


    setText(
        "cityValue",
        infrastructure.city || "—"
    );


    setText(
        "ispValue",
        infrastructure.isp || "—"
    );


    setText(
        "asnValue",
        infrastructure.asn || "—"
    );


    // --------------------------------------------------------
    // AUTHENTICATION
    // --------------------------------------------------------

    setText(
        "spfValue",
        authentication.spf || "—"
    );


    setText(
        "dkimValue",
        authentication.dkim || "—"
    );


    setText(
        "dmarcValue",
        authentication.dmarc || "—"
    );


    // --------------------------------------------------------
    // INDICATORS
    // --------------------------------------------------------

    displayList(
        "domainsValue",
        indicators.domains || []
    );


    displayList(
        "urlsValue",
        indicators.urls || []
    );


    // --------------------------------------------------------
    // FORENSIC EVIDENCE
    // --------------------------------------------------------

    setText(
        "senderValue",
        forensic.sender ||
        data.sender ||
        "—"
    );


    setText(
        "recipientValue",
        forensic.recipient ||
        data.recipient ||
        "—"
    );


    setText(
        "subjectValue",
        forensic.subject ||
        data.subject ||
        "—"
    );


    setText(
        "filenameValue",
        forensic.filename ||
        data.filename ||
        "—"
    );


    setText(
        "sha256Value",
        forensic.sha256 ||
        data.sha256 ||
        "—"
    );


    setText(
        "timestampValue",
        forensic.timestamp ||
        data.timestamp ||
        "—"
    );


    // --------------------------------------------------------
    // MESSAGE PREVIEW
    // --------------------------------------------------------

    const preview =
        data.message_preview ||
        "No message preview available.";


    setText(
        "messagePreview",
        preview
    );

}


// ============================================================
// SET TEXT SAFELY
// ============================================================

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {
        return;
    }


    element.textContent =
        value ?? "—";

}


// ============================================================
// DISPLAY LIST
// ============================================================

function displayList(
    elementId,
    items
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {
        return;
    }


    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {

        element.innerHTML =
            `<div class="indicator-item">
                None detected
             </div>`;

        return;

    }


    element.innerHTML =
        items
            .map(
                item =>
                    `<div class="indicator-item">
                        ${escapeHTML(item)}
                     </div>`
            )
            .join("");

}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {

    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}