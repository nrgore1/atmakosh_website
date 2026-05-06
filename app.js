document.getElementById("year").textContent = new Date().getFullYear();

const revealables = document.querySelectorAll(".card, .paper-card, .hero-card, .stack-item, .cta-panel");
const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.14 });

revealables.forEach((node) => {
  node.classList.add("reveal");
  observer.observe(node);
});


const contactForm = document.getElementById("contactForm");
const formStatus = document.getElementById("formStatus");
const startedAt = document.getElementById("formStartedAt");
if (startedAt) startedAt.value = Math.floor(Date.now() / 1000).toString();

function setFormStatus(message, type = "") {
  if (!formStatus) return;
  formStatus.textContent = message;
  formStatus.className = `form-status ${type}`.trim();
}

if (contactForm) {
  contactForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setFormStatus("Submitting…");

    if (!contactForm.checkValidity()) {
      contactForm.reportValidity();
      setFormStatus("Please complete the required fields.", "error");
      return;
    }

    const submitButton = contactForm.querySelector('button[type="submit"]');
    submitButton.disabled = true;

    try {
      const response = await fetch(contactForm.action, {
        method: "POST",
        body: new FormData(contactForm),
        headers: { "Accept": "application/json" }
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(payload.message || "Submission failed.");
      }
      contactForm.reset();
      if (startedAt) startedAt.value = Math.floor(Date.now() / 1000).toString();
      setFormStatus(payload.message || "Thank you. Your inquiry has been received.", "success");
    } catch (error) {
      setFormStatus(error.message || "Something went wrong. Please try again.", "error");
    } finally {
      submitButton.disabled = false;
    }
  });
}
