/* Mini-SOC M1 — petites interactions frontend. */
(function () {
    const qtyInputs = document.querySelectorAll('[data-qty]');
    qtyInputs.forEach(function (input) {
        input.addEventListener('change', function () {
            if (parseInt(input.value || '1', 10) < 1) {
                input.value = 1;
            }
        });
    });

    /* Vulnérabilité volontaire : DOM-based XSS via fragment #promo=... */
    const promoTarget = document.querySelector('[data-promo-message]');
    if (promoTarget && window.location.hash.indexOf('#promo=') === 0) {
        const rawMessage = decodeURIComponent(window.location.hash.substring(7));
        promoTarget.innerHTML = rawMessage;
    }
})();
