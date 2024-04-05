import csv
import requests
from bs4 import BeautifulSoup

def scrape_monster_jobs(title, location):
    url = f"https://www.monster.com/jobs/search/?q={title.replace(' ', '-').lower()}&where={location.replace(' ', '-')}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        print(soup)
        job_listings = soup.find_all('section', class_='card-content')
        
        jobs_data = []
        for job in job_listings:
            title = job.find('h2', class_='title').text.strip()
            company = job.find('div', class_='company').text.strip()
            location = job.find('div', class_='location').text.strip()
            date_posted = job.find('time').text.strip()
            link = job.find('a')['href']
            
            jobs_data.append([title, company, location, date_posted, link])
        
        return jobs_data
    else:
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return None

def save_to_csv(data, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Title', 'Company', 'Location', 'Date Posted', 'Link'])
        writer.writerows(data)
    print(f"Data has been saved to {filename}")

if __name__ == "__main__":
    job_title = input("Enter job title: ")
    job_location = input("Enter job location: ")

    jobs_data = scrape_monster_jobs(job_title, job_location)
    print(jobs_data)
    # if jobs_data:
    #     save_to_csv(jobs_data, 'monster_jobs.csv')
