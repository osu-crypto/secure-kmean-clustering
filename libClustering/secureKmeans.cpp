#include <iostream>
#include <math.h>
#include <algorithm>
#include <stdlib.h>
#include <vector>
#include <time.h>

using namespace std;

class Item
{
private:
	int idxItem, idxCluster;
	vector<double> vecVal;
	int totalVals;

public:
	Item(int idxItem, vector<double>& vecVal)
	{
		this->idxItem = idxItem;
		totalVals = vecVal.size();

		for(int i = 0; i < totalVals; i++)
			this->vecVal.push_back(vecVal[i]);

		idxCluster = -1;
	}

	int getID()
	{
		return idxItem;
	}

	void setCluster(int idxCluster)
	{
		this->idxCluster = idxCluster;
	}

	int getCluster()
	{
		return idxCluster;
	}

	double getValue(int idx)
	{
		return vecVal[idx];
	}

	int getTotalValues()
	{
		return totalVals;
	}

	void addValue(double value)
	{
		vecVal.push_back(value);
	}

	
};

class Cluster
{
private:
	int idxCluster;
	vector<double> clusVals;
	vector<Item> points;

public:
	Cluster(int idxCluster, Item item)
	{
		this->idxCluster = idxCluster;

		int totalVals = item.getTotalValues();

		for(int i = 0; i < totalVals; i++)
			clusVals.push_back(item.getValue(i));

		points.push_back(item);
	}

	void addItem(Item item)
	{
		items.push_back(item);
	}

	bool removeItem(int idxItem)
	{
		int totalItems = items.size();

		for(int i = 0; i < totalItems; i++)
		{
			if(items[i].getID() == idxItem)
			{
				items.erase(items.begin() + i);
				return true;
			}
		}
		return false;
	}

	double getCentralValue(int idx)
	{
		return clusVals[idx];
	}

	void setCentralValue(int idx, double value)
	{
		clusVals[idx] = value;
	}

	Item getItem(int getItem)
	{
		return items[getItem];
	}

	int getTotalItems()
	{
		return items.size();
	}

	int getID()
	{
		return idxCluster;
	}
};

class SKMean
{
private:
	int K; // number of clusters
	int totalVals, totalItems, maxIter; //max iteration
	vector<Cluster> clusters;

	// return ID of nearest center 
	int getIDNearestCenter(Item item)
	{
		double sum = 0.0, min_dist;
		int idxCluster_center = 0;

		for(int i = 0; i < totalVals; i++)
		{
			sum += pow(clusters[0].getCentralValue(i) -
					   item.getValue(i), 2.0);
		}

		min_dist = sqrt(sum);

		for(int i = 1; i < K; i++)
		{
			double dist;
			sum = 0.0;

			for(int j = 0; j < totalVals; j++)
			{
				sum += pow(clusters[i].getCentralValue(j) -
						   item.getValue(j), 2.0);
			}

			dist = sqrt(sum);

			if(dist < min_dist)
			{
				min_dist = dist;
				idxCluster_center = i;
			}
		}

		return idxCluster_center;
	}

public:
	SKMean(int K, int totalItems, int totalVals, int maxIter)
	{
		this->K = K;
		this->totalItems = totalItems;
		this->totalVals = totalVals;
		this->maxIter = maxIter;
	}

	void run(vector<Item> & items)
	{
		if(K > totalItems)
			return;

		vector<int> lstIdx;

		for(int i = 0; i < K; i++)
		{
			while(true)
			{
				int idxItem = rand() % totalItems;

				if(find(lstIdx.begin(), lstIdx.end(),
						idxItem) == lstIdx.end())
				{
					lstIdx.push_back(idxItem);
					items[idxItem].setCluster(i);
					Cluster cluster(i, items[idxItem]);
					clusters.push_back(cluster);
					break;
				}
			}
		}

		int iter = 1;

		while(true)
		{
			bool done = true;

			for(int i = 0; i < totalItems; i++)
			{
				int idxOldCluster = items[i].getCluster();
				int idxNewCluster = getIDNearestCenter(items[i]);

				if(idxOldCluster != idxNewCluster)
				{
					if(idxOldCluster != -1)
						clusters[idxOldCluster].removeItem(items[i].getID());

					items[i].setCluster(idxNewCluster);
					clusters[idxNewCluster].addItem(items[i]);
					done = false;
				}
			}

			// update cluster
			for(int i = 0; i < K; i++)
			{
				for(int j = 0; j < totalVals; j++)
				{
					int cntCluster = clusters[i].getTotalItems();
					double sum = 0.0;

					if(cntCluster > 0)
					{
						for(int p = 0; p < cntCluster; p++)
							sum += clusters[i].getItem(p).getValue(j);
						clusters[i].setCentralValue(j, sum / cntCluster);
					}
				}
			}

			if(done == true || iter >= maxIter)
			{
				break;
			}

			iter++;
		}

	}
};

int main(int argc, char *argv[])
{

	int totalItems=100, totalVals=100, K=10, maxIter=10;


	vector<Item> items;

	//random data
	for(int i = 0; i < totalItems; i++)
	{
		vector<double> vecVal;

		for(int j = 0; j < totalVals; j++)
		{
			double value;
			value=rand()%100;
			vecVal.push_back(value);
		}

		
			Item p(i, vecVal);
			items.push_back(p);
		
	}

	SKMean kmeans(K, totalItems, totalVals, maxIter);
	kmeans.run(items);

	return 0;
}
