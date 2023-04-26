#!/bin/bash

touch /usr/bin/terminator
echo "#!/bin/bash" > /usr/bin/terminator
echo "python3 terminator.py" >> /usr/bin/terminator
echo "" >> /usr/bin/terminator
