const cart = JSON.parse(localStorage.getItem('cart') || '{"items":[]}');

function addToCart(productId, name, price) {
  const existing = cart.items.find(i => i.productId === productId);
  if (existing) {
    existing.quantity += 1;
  } else {
    cart.items.push({ productId, name, price, quantity: 1 });
  }
  localStorage.setItem('cart', JSON.stringify(cart));
  showCartNotice();
}

function showCartNotice() {
  const notice = document.createElement('div');
  notice.textContent = 'Added to cart!';
  notice.style.cssText = 'position:fixed;bottom:1rem;right:1rem;background:#1a1a2e;color:#fff;padding:.75rem 1.25rem;border-radius:6px;z-index:9999;font-size:.875rem;';
  document.body.appendChild(notice);
  setTimeout(() => notice.remove(), 2000);
}

function getCartContents() {
  return cart;
}
