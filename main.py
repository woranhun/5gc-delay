import matplotlib.pyplot as plt

from delaycalculator import DelayCalculator

if __name__ == "__main__":
    numOfUEs = [1, 2, 3, 5, 7, 9]
    datas = list()
    for i in numOfUEs:
        data = DelayCalculator("./pcaps/jocap/jo{0}dbUE.pcap".format(str(i)))
        datas.append(data.calculate())

    plt.figure(figsize=(14, 5))
    plt.plot(numOfUEs, datas, marker='o', markerfacecolor='blue', markersize=12,)
    plt.ylim([0, 1])
    plt.xlabel("Number Of UEs")
    plt.ylabel("seconds")
    plt.title("AMF delay")
    for i, j in zip(numOfUEs, datas):
        plt.annotate(str(round(j, 6)) + " s", xy=(i, j + 0.05), fontsize=12, color='black')
    plt.show()
