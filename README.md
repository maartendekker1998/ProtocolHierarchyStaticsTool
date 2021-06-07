# ProtocolHierarchyStaticsTool
A python script that runs tshark protocol hierarcy statistics for multiple PCAPs and writes the results to a Redis DB.

Tshark PHS returns a text based output. This output is regexed to retrive the relevant information, and then put into a Redis Database.
The script also contains a codebase for random sampling a dataset of PCAPs to a suggested size.
