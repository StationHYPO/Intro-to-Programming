# File: section5_challenges/01_trip_calculator.py
# Road trip planning calculator

distance_km = float(input("Enter trip distance in kilometers: "))
fuel_efficiency = float(input("Enter your car's fuel efficiency (L/100km): "))
fuel_price = float(input("Enter fuel price per liter: "))

# Calculations
distance_miles = distance_km * 0.621371
fuel_needed = (distance_km / 100) * fuel_efficiency
total_fuel_cost = fuel_needed * fuel_price

# Travel time calculations
speed_city = 50  # km/h
speed_highway = 100  # km/h

time_city = distance_km / speed_city
time_highway = distance_km / speed_highway

print("\n=== Trip Summary ===")
print(f"Distance: {distance_km:.1f} km ({distance_miles:.1f} miles)")
print(f"Estimated fuel needed: {fuel_needed:.1f} L")
print(f"Estimated fuel cost: ${total_fuel_cost:.2f}")
print(f"Estimated time at city speeds: {time_city:.1f} hours")
print(f"Estimated time at highway speeds: {time_highway:.1f} hours")