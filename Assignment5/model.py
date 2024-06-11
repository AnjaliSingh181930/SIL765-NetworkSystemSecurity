import torch
import torch.optim
import torch.nn as nn
import torch.nn.functional as F

import torchvision
import os
from torchvision import transforms

from typing import Tuple
from torch.utils.data import DataLoader

import matplotlib.pyplot as plt


# Define the model architecture
class ANNClassifier(nn.Module):
    def __init__(self, train_params: dict):
        super(ANNClassifier, self).__init__()
        self.train_params = train_params
        self._define_model()
        self.criterion = self._define_criterion()
        self.optimizer = self._define_optimizer()

    def _define_model(self) -> None:
        """
        Define the model architecture
        return: None
        """
        self.fc1 = nn.Linear(28 * 28, 128)  # Input size: 28*28, output size: 128
        self.fc2 = nn.Linear(128, 64)       # Input size: 128, output size: 64
        self.fc3 = nn.Linear(64, 10)

    def _define_criterion(self) -> nn.Module:
        """
        Define the criterion (loss function) to use for the model
        return: nn.Module
        """
        criterion_name = self.train_params.get("criterion", "CrossEntropy")
        
        if criterion_name == "CrossEntropy":
            return nn.CrossEntropyLoss()
        elif criterion_name == "MSE":
            return nn.MSELoss()
        else:
            raise ValueError(f"Unsupported criterion: {criterion_name}")

    def _define_optimizer(self) -> torch.optim.Optimizer:
        """
        Define the optimizer to use for the model
        return: torch.optim.Optimizer
        """
        optimizer_name = self.train_params.get("optimizer", "SGD")
        learning_rate = self.train_params.get("learning_rate", 0.01)

        if optimizer_name == "SGD":
            return torch.optim.SGD(self.parameters(), lr=learning_rate)
        elif optimizer_name == "Adam":
            return torch.optim.Adam(self.parameters(), lr=learning_rate)
        elif optimizer_name == "RMSprop":
            return torch.optim.RMSprop(self.parameters(), lr=learning_rate)
        else:
            raise ValueError(f"Unsupported optimizer: {optimizer_name}")
    
    def get_dataloaders(self) -> Tuple[DataLoader, DataLoader]:
        """
        Create the dataloaders(train and test) for the MNIST dataset
        return: DataLoader, DataLoader
        """
        # Define transformations
        transform = transforms.Compose([
            transforms.ToTensor(),
        ])

        # Load MNIST dataset
        mnist_train = torchvision.datasets.MNIST(root="./data", train=True, download=True, transform=transform)
        mnist_test = torchvision.datasets.MNIST(root="./data", train=False, download=True, transform=transform)
        
        # Splitting MNIST dataset into train and test sets
        train_size = int(0.6 * len(mnist_train))
        test_size = len(mnist_train) - train_size
        train_dataset, _ = torch.utils.data.random_split(mnist_train, [train_size, test_size])
        
        
         # Create directories if they don't exist
        os.makedirs("train data", exist_ok=True)
        os.makedirs("test data", exist_ok=True)

        # Saving train and test datasets
        for i, (image, label) in enumerate(train_dataset):
            torch.save((image, label), f"train data/{i}.pt")
        for i, (image, label) in enumerate(mnist_test):
            torch.save((image, label), f"test data/{i}.pt")

        # Creating data loaders
        train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=self.train_params["batch_size"], shuffle=True)
        test_loader = torch.utils.data.DataLoader(mnist_test, batch_size=self.train_params["batch_size"], shuffle=False)

        return train_loader, test_loader
    def forward(self, x):
        x = x.view(-1, 28 * 28)  # Flatten the input tensor
        x = F.relu(self.fc1(x))   # Pass through the first fully connected layer with ReLU activation
        x = F.relu(self.fc2(x))   # Pass through the second fully connected layer with ReLU activation
        x = self.fc3(x)           # Pass through the third fully connected layer (output layer)
        return x
    def train_step(self, train_loader, val_loader):
        train_losses = []
        train_accuracy = []
        val_losses = []
        val_accuracy = []

        for epoch in range(self.train_params["epochs"]):
            self.train()
            running_loss = 0.0
            correct = 0
            total = 0

            for images, labels in train_loader:
                self.optimizer.zero_grad()
                outputs = self.forward(images)
                loss = self.criterion(outputs, labels)
                loss.backward()
                self.optimizer.step()

                _, predicted = torch.max(outputs.data, 1)
                total += labels.size(0)
                correct += (predicted == labels).sum().item()
                running_loss += loss.item()

            epoch_loss = running_loss / len(train_loader)
            epoch_accuracy = correct / total
            
            train_losses.append(epoch_loss)
            train_accuracy.append(epoch_accuracy)

            print(f"Epoch [{epoch + 1}/{self.train_params['epochs']}], "
                  f"Train Loss: {epoch_loss:.4f}, Train Accuracy: {epoch_accuracy:.4f}")

            # Validation
            self.eval()
            val_running_loss = 0.0
            val_correct = 0
            val_total = 0

            with torch.no_grad():
                for val_images, val_labels in val_loader:
                    val_outputs = self.forward(val_images)
                    val_loss = self.criterion(val_outputs, val_labels)
                    val_running_loss += val_loss.item()

                    _, val_predicted = torch.max(val_outputs.data, 1)
                    val_total += val_labels.size(0)
                    val_correct += (val_predicted == val_labels).sum().item()

            val_epoch_loss = val_running_loss / len(val_loader)
            val_epoch_accuracy = val_correct / val_total
            val_losses.append(val_epoch_loss)
            val_accuracy.append(val_epoch_accuracy)

            print(f"Epoch [{epoch + 1}/{self.train_params['epochs']}], "
                  f"Validation Loss: {val_epoch_loss:.4f}, Validation Accuracy: {val_epoch_accuracy:.4f}")

        return {"train_losses": train_losses, "train_accuracy": train_accuracy,
                "val_losses": val_losses, "val_accuracy": val_accuracy}

    def infer(self):
        """
        Evaluate the model
        return: float
        """
        correct = 0
        total = 0

        # Set model to evaluation mode
        self.eval()

        with torch.no_grad():
            for images, labels in self.test_loader:
                # Forward pass
                outputs = self.forward(images)
                _, predicted = torch.max(outputs.data, 1)
                total += labels.size(0)
                correct += (predicted == labels).sum().item()

        # Compute test accuracy
        test_accuracy = 100 * correct / total
        return test_accuracy

    def plot_loss(self, results: dict)  -> None:
        """
        Plot the curve loss v/s epochs
        results: dict
        return: None
        """
        plt.plot(results['train_losses'], label='Training Loss')
        plt.plot(results['val_losses'], label='Validation Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.title('Training and Validation Loss Curve')
        plt.legend()
        plt.savefig("plots/training_validation_loss_curve.png")
        plt.show()


    def save(self, file_path: str):
        """
        Save the model
        file_path: str
        return: None
        """
        torch.save(self.state_dict(), file_path)


if __name__ == '__main__':

    train_params = {
        "batch_size": 1,
        "learning_rate": 0.01,
        "epochs": 20
    }

    ## Training ##

    # Create the model
    model = ANNClassifier(train_params)

    # Load the data
    train_loader, test_loader = model.get_dataloaders()
    model.train_loader = train_loader
    model.test_loader = test_loader

    # Train the model and return everything you need to report
    # and plot using a dictionary
    results: dict = model.train_step(train_loader, test_loader)
    train_accuracy = results["train_accuracy"][-1]
    val_accuracy = results["val_accuracy"][-1]
    
    # Plot the loss curve
    model.plot_loss(results)

    # Save the model
    model.save(file_path='model.pth')

    ## Evaluation ##

    # Load the model
    eval_model = ANNClassifier(train_params)
    eval_model.load_state_dict(torch.load('model.pth'))

    # Set the datasets
    train_loader, test_loader = eval_model.get_dataloaders()
    eval_model.train_loader = train_loader
    eval_model.test_loader = test_loader

    # Evaluate the model
    test_accurary = eval_model.infer()
    print(f'Training Accuracy: {train_accuracy*100:.2f}%')
    print(f'Validation Accuracy: {val_accuracy*100:.2f}%')
    print(f'Test Accuracy: {test_accurary:.2f}%')
