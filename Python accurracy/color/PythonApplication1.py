import numpy as np
import matplotlib.pyplot as plt

# # Create data
# N = 60
# g1 = (0.6 + 0.6 * np.random.rand(N), np.random.rand(N))
# g2 = (0.4+0.3 * np.random.rand(N), 0.5*np.random.rand(N))
# g3 = (0.3*np.random.rand(N),0.3*np.random.rand(N))

# read from txt file
data = [[], [], [],[]]
with open('sizes1.arff.txt', 'r') as f:
    for line in f.readlines():
        line = line.strip()
        x, y, g = line.split(',')
        x = float(x)
        y = float(y)
        g = int(g)
        data[g].append((x,y))

# data = (g1, g2, g3)
colors = ("red", "green", "blue","yellow")
groups = ("coffee", "tea", "water", "water")

# Create plot
fig = plt.figure()
ax = fig.add_subplot(1, 1, 1)

for data, color, group in zip(data, colors, groups):
    x, y = np.array(data).T
    ax.scatter(x, y, alpha=0.8, c=color, edgecolors='none', s=30, label=group)

plt.title('Matplot scatter plot')
plt.legend(loc=2)
plt.show()