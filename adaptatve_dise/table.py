import pandas as pd
import matplotlib.pyplot as plt

# Define the data columns
columns = ['n', 't', 'Batch Size', 'Batches/min', 'Msg/min', 'Throughput (msg/s)']

# Example data (replace this with actual data if needed)
data = [
    [12, 4, 200, 3247705, 649541000, 10825683.333333334],
    [12, 4, 400, 2651955, 1060782000, 17679700.0],
    [24, 8, 50, 1848177, 92408850, 1540417.5],
    [24, 8, 100, 1800203, 180020300, 3000338.3333333335],
    [24, 8, 200, 1702051, 340410200, 5673503.333333333],
    [24, 8, 400, 1467557, 587022800, 9783713.333333334],
    [50, 8, 50, 1501157, 75057850, 1258964.1666666667],
    [40, 10, 100, 1459868, 145986800, 2433113.3333333335],
    [40, 10, 200, 1381029, 276205800, 4603430.0],
    [40, 10, 400, 1991989, 479675600, 7994593.333333333]
]

# Create a DataFrame
df = pd.DataFrame(data, columns=columns)

# Display the DataFrame
print(df)

# Plot throughput vs batch size
plt.figure(figsize=(10, 6))
plt.plot(df['Batch Size'], df['Throughput (msg/s)'], marker='o', label='Throughput')
plt.title('Throughput vs Batch Size')
plt.xlabel('Batch Size')
plt.ylabel('Throughput (msg/s)')
plt.legend()
plt.grid()
plt.show()
