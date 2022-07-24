from cli.tree import list_files

K = list_files("tmp")
# for k in K:
#   print(k)

for i in K:
  if "requirment.txt" in i:
    print(i)
    break
