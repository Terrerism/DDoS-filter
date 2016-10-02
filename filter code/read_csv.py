__author__ = 'kwon'
import pandas as pd
import numpy as np
import pickle
data1=pd.read_csv('label0_test.csv', sep=',',header=None).as_matrix()
#data2=pd.read_csv('label1_test.csv', sep=',',header=None).as_matrix()
#data3=pd.read_csv('label2_test.csv', sep=',',header=None).as_matrix()
data = np.vstack((data1))
print data1[0]
#print data2[0]
#print data3[0]

label=np.zeros(len(data1))
#label=np.hstack((label,np.ones(len(data2))))
#label=np.hstack((label,np.ones(len(data3))*2))
gen=(data,label)
pickle.dump(gen,open('gen_test.pkl','wb'))


data1=pd.read_csv('label0.csv', sep=',',header=None).as_matrix()
data2=pd.read_csv('label1.csv', sep=',',header=None).as_matrix()
data3=pd.read_csv('label2.csv', sep=',',header=None).as_matrix()
data = np.vstack((data1,data2,data3))
print data1[0]
print data2[0]
print data3[0]

label=np.zeros(len(data1))
label=np.hstack((label,np.ones(len(data2))))
label=np.hstack((label,np.ones(len(data3))*2))
gen=(data,label)
pickle.dump(gen,open('gen.pkl','wb'))
