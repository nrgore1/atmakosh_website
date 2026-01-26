// Subtle “vibration” interaction: pointer-based ripple offset on mandala.
(() => {
  const mandala = document.querySelector(".bg__mandala");
  if (!mandala) return;

  let raf = null;
  window.addEventListener("pointermove", (e) => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = null;
      const x = (e.clientX / window.innerWidth) - 0.5;
      const y = (e.clientY / window.innerHeight) - 0.5;
      mandala.style.transform = `translate(${x * -18}px, ${y * 18}px) rotate(${x * 8}deg)`;
    });
  }, { passive: true });
})();
