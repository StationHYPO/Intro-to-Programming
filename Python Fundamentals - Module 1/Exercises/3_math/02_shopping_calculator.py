# File: section3_math/02_shopping_calculator.py
# Shopping cart calculator with tax

item1_price = 14.99
item2_price = 29.99
tax_rate = 0.08  # 8% sales tax

subtotal = item1_price + item2_price
tax_amount = subtotal * tax_rate
total = subtotal + tax_amount

print(f"Subtotal: ${subtotal:.2f}")
print(f"Tax: ${tax_amount:.2f}")
print(f"Total: ${total:.2f}")