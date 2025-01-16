# L1WhoAndWhere.py

# Variable that can be imported by other files
iAm = "I am the Alpha and the Omega."

def calculate_trip_details():
   """Collects user input and calculates trip details"""
   # Get basic information
   name = input("Enter your name. ")
   print()
   
   vehicle = input(f"Hello {name}! What make/model vehicle do you drive? ")
   print()
   
   mpg = float(input(f"What MPG does your {vehicle} get? "))
   print()
   
   place = input(f"Where do you like to drive your {vehicle}? ")
   print()
   
   # Get trip specifics
   distance = float(input(f"How far is {place} in miles? "))
   print()
   
   gas_price = float(input("What's the current gas price? $"))
   print()
   
   mph = float(input(f"How fast do you usually drive to {place}? MPH: "))
   print()
   
   # Calculate results
   gallons = distance / mpg
   cost = gallons * gas_price
   time = distance / mph
   
   # Display results
   print(f"\nTrip Summary for {name}:")
   print(f"Destination: {place}")
   print(f"Fuel needed: {gallons:.2f} gallons")
   print(f"Trip cost: ${cost:.2f}")
   print(f"Travel time: {time:.2f} hours")

# Only run the interactive part if this file is run directly
if __name__ == "__main__":
   calculate_trip_details()