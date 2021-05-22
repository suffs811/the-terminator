#!/usr/bin/env python3

'''
a program that lets you choose a mood/explression 
and then gives you a bible verse for encouragement.
'''

verses = {
"crying":"Blessed are those who mourn, for they will be comforted.\n[Matthew 5:4]",
"sad":"God is our refuge and strength, an ever-resent help in trouble.\n[Psalm 46:1]",
"depressed":"The Lord is near to the brokenhearted and saves those who are crushed in spririt.\n[Psalm 34:18]",
"unsatisfied":"The Lord is my shephard, I shall not want.\n[Psalm 23:1]",
"hopeless":"May the God of hope fill you with all joy and peace in believing, so that by the poower of the Holy Spirit you may abound in hope.\n[Romans 15:13]",
"empty":"Then our mouth was filled with laughter, and our tongue with shouts of joy; then they said among the nations, 'The LORD has done great things for them.'\n[Psalm 126:2]",
"lost":"For the Son of Man came to seek and to save the lost.\n[Luke 19:10]",
"numb":"He lifted me out of the slimy pit, and out of the mud and mire; He set my feet on a rock and gave me a firm place to stand.\n[Psalm 40:2]",
"whatevs":"Being confident of this, that He who began a good work in you will carry it on to completion until the day of Christ Jesus.\n[Philippians 1:6]",
"hopeful":"The Lord, the Lord God, compassionate and gracious,\nslow to anger, and abounding in lovingkindness for thousands,\nwho forgives iniquity, trangression and sin;\nyet He will by no means leave the guilty unpunished,\nvisiting the iniquity of fathers on the children and on the grandchildren\nto the third and fourth generations.\n[Exodus 34:6-7]",
"content":"The young lions suffer want and hunger; but those who seek the Lord lack no good thing.\n[Psalm 34:10]",
"thankful":"Give thanks to the LORD, for He is good, for His faithfulness is everlasting.\n[Psalm 136:1]",
"joyful":"Blessed are those who trust in the LORD,\nwhose trust is the LORD.\nThey shall be like a tree planted by water,\nsending out its roots by the stream.\nIt shall not fear when heat comes,\nand its leaves shall stay green;\nin the year of drought it is not anxious,\nand it does not cease to bear fruit.\n[Jeremiah 17:7-8]",
"tears of joy":"Praise the LORD.\nPraise the LORD, you His servants; praise the name of the LORD.\nLet the name of the LORD be praised, both now and forevermore.\nFrom the rising of the sun to the place where it sets,\nthe name of the LORD is to be praised.\n[Psalm 113:1-3]"
}

cont = False

while cont == False:
	print("\nHow are ya feeling today?\n\ncrying\nsad\ndepressed\nunsatisfied\nhopless\nempty\nlost\nnumb\nwhatevs\nhopeful\ncontent\nthankful\njoyful\ntears of joy\n")
	feeling = input(": ")
	feeling_l = feeling.lower()

	if feeling_l in verses:
		print("--")
		print(verses[feeling_l])
		print("--")
	else:
		print("Please select an emotion :)")

	print("Another verse? ")
	print("y, n")
	c = input(": ")
	if c == "n":
		print("*** Have a great day ***")
		cont = True
