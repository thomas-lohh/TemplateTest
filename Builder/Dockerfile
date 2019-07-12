# Use an official Python runtime as a parent image
FROM {base_image}

# Set the working directory to /app
WORKDIR /app

RUN apt-get update
RUN apt-get install -y gcc
RUN apt-get install -y g++
RUN pip3 install -U spacy
RUN python3 -m spacy download en

RUN pip3 install https://download.pytorch.org/whl/cpu/torch-1.0.0-cp36-cp36m-linux_x86_64.whl
RUN pip3 install torchvision==0.2.2

# Install any needed packages specified in requirements.txt
COPY requirements.txt /app
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Install dependencies
RUN apt-get install -y libglib2.0-0 libsm6 libfontconfig1 libxrender1 libxtst6 libxi6

# Copy the current directory contents into the container at /app
COPY ./app /app

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World
ENV PYTHONPATH /app/ML

# Set the working directory 
WORKDIR {working_dir}

# Run app.py when the container launches
CMD ["python", "service.py", "service.options.json"]
