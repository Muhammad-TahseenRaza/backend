document.addEventListener("DOMContentLoaded", () => {
    const copyButtons = document.querySelectorAll(".copy-btn");

    copyButtons.forEach((btn) => {
        btn.addEventListener("click", async () => {
            const link = btn.getAttribute("data-link");

            try {
                await navigator.clipboard.writeText(link);
                alert(`Copied: ${link}`);
            } catch (err) {
                console.error("Failed to copy: ", err);
            }
        });
    });
});