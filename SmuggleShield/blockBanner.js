(function() {
  let bannerStartTime = null;
  let hideTimeout = null;
  
  function createBanner() {
    if (document.getElementById('smuggleshield-block-banner')) {
      return;
    }

    const banner = document.createElement('div');
    banner.id = 'smuggleshield-block-banner';
    
    const styles = {
      position: 'fixed',
      top: '16px',
      right: '16px',
      maxWidth: '400px',
      backgroundColor: '#d32f2f',
      color: '#fff',
      padding: '12px 16px',
      borderRadius: '6px',
      display: 'flex',
      alignItems: 'center',
      zIndex: '2147483647',
      boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
      fontSize: '14px',
      lineHeight: '1.4',
      transition: 'transform 0.3s ease-in-out, opacity 0.3s ease-in-out',
      transform: 'translateY(-100%)',
      opacity: '0'
    };
    
    Object.assign(banner.style, styles);
    
    const logo = document.createElement('img');
    logo.src = chrome.runtime.getURL('icon/SmuggleShield.png');
    Object.assign(logo.style, {
      width: '20px',
      height: '20px',
      marginRight: '12px',
      borderRadius: '4px',
      flexShrink: '0'
    });
    
    const message = document.createElement('span');
    message.textContent = 'Suspicious content blocked';
    message.style.flex = '1';
    
    const closeButton = document.createElement('button');
    Object.assign(closeButton.style, {
      background: 'none',
      border: 'none',
      color: '#fff',
      cursor: 'pointer',
      padding: '4px',
      marginLeft: '12px',
      opacity: '0.8',
      transition: 'opacity 0.2s',
      flexShrink: '0',
      width: '20px',
      height: '20px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    });
    closeButton.innerHTML = '✕';
    closeButton.addEventListener('mouseover', () => closeButton.style.opacity = '1');
    closeButton.addEventListener('mouseout', () => closeButton.style.opacity = '0.8');
    closeButton.addEventListener('click', () => hideBanner(true));
    
    banner.appendChild(logo);
    banner.appendChild(message);
    banner.appendChild(closeButton);
    
    document.body.appendChild(banner);
    
    bannerStartTime = Date.now();
    requestAnimationFrame(() => {
      banner.style.transform = 'translateY(0)';
      banner.style.opacity = '1';
    });
  }
  
  function removeBanner() {
    const banner = document.getElementById('smuggleshield-block-banner');
    if (banner) {
      banner.style.transform = 'translateY(-100%)';
      banner.style.opacity = '0';
      banner.addEventListener('transitionend', () => {
        if (banner.parentNode) {
          banner.parentNode.removeChild(banner);
          bannerStartTime = null;
        }
      });
    }
  }

  function showBanner() {
    if (hideTimeout) {
      clearTimeout(hideTimeout);
      hideTimeout = null;
    }
    createBanner();
  }

  function hideBanner(force = false) {
    const banner = document.getElementById('smuggleshield-block-banner');
    if (!banner) return;

    const elapsed = Date.now() - (bannerStartTime || Date.now());
    
    if (force || elapsed >= 3000) {
      removeBanner();
    } else {
      if (hideTimeout) clearTimeout(hideTimeout);
      hideTimeout = setTimeout(() => {
        removeBanner();
        hideTimeout = null;
      }, 3000 - elapsed);
    }
  }
  
  window.SmuggleShieldBanner = {
    show: showBanner,
    hide: hideBanner
  };
})(); 
